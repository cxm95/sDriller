import os
import sys
import signal
import logging.config
import driller
import argparse
import subprocess
import multiprocessing

import angr
from angr.sim_type import SimTypeString


try:
    import cPickle as pickle
except:
    import pickle


l = logging.getLogger("local_callback")

def _run_drill(drill, fuzz, _path_to_input_to_drill, length_extension=None):
    _binary_path = fuzz.binary_path
    _fuzzer_out_dir = fuzz.out_dir
    _bitmap_path = os.path.join(_fuzzer_out_dir, 'fuzzer-master', "fuzz_bitmap")
    _timeout = drill._worker_timeout
    l.warning("starting drilling of %s, %s", os.path.basename(_binary_path), os.path.basename(_path_to_input_to_drill))
    args = (
        "timeout", "-k", str(_timeout+10), str(_timeout),
        sys.executable, os.path.abspath(__file__),
        _binary_path, _fuzzer_out_dir, _bitmap_path, _path_to_input_to_drill
    )
    if length_extension:
        args += ('--length-extension', str(length_extension))

    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    print(p.communicate())


class LocalCallback(object):
    def __init__(self, num_workers=1, worker_timeout=10*60, length_extension=None):
        self._already_drilled_inputs = set()

        self._num_workers = num_workers
        self._running_workers = []
        self._worker_timeout = worker_timeout
        self._length_extension = length_extension

    @staticmethod
    def _queue_files(fuzz, fuzzer='fuzzer-master'):
        '''
        retrieve the current queue of inputs from a fuzzer
        :return: a list of strings which represent a fuzzer's queue
        '''

        queue_path = os.path.join(fuzz.out_dir, fuzzer, 'queue')
        queue_files = filter(lambda x: x != ".state", os.listdir(queue_path))
        queue_files = [os.path.join(queue_path, q) for q in queue_files]

        return queue_files

    def driller_callback(self, fuzz):
        l.warning("Driller stuck callback triggered!")
        # remove any workers that aren't running
        self._running_workers = [x for x in self._running_workers if x.is_alive()]

        # get the files in queue
        queue = self._queue_files(fuzz)
        #for i in range(1, fuzz.fuzz_id):
        #    fname = "fuzzer-%d" % i
        #    queue.extend(self.queue_files(fname))

        # start drilling
        not_drilled = set(queue) - self._already_drilled_inputs
        if len(not_drilled) == 0:
            l.warning("no inputs left to drill")

        while len(self._running_workers) < self._num_workers and len(not_drilled) > 0:
            to_drill_path = list(not_drilled)[0]
            not_drilled.remove(to_drill_path)
            self._already_drilled_inputs.add(to_drill_path)

            proc = multiprocessing.Process(target=_run_drill, args=(self, fuzz, to_drill_path),
                    kwargs={'length_extension': self._length_extension})
            proc.start()
            self._running_workers.append(proc)

    __call__ = driller_callback

    def kill(self):
        for p in self._running_workers:
            try:
                p.terminate()
                os.kill(p.pid, signal.SIGKILL)
            except OSError:
                pass

# func table for libc functions
class hook_setbuf(angr.SimProcedure):
    def run(self, stream, buf): # argument here
        self.ret()

class hook_alarm(angr.SimProcedure):     
    def run(self,time):
        self.ret()

class hook_strtok(angr.SimProcedure):
    # modified from posix_strtok_r
    def run(self, str_ptr, delim_ptr, str_strlen=None, delim_strlen=None):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())
        malloc = angr.SIM_PROCEDURES['libc']['malloc']
        token_ptr = self.inline_call(malloc, self.state.libc.strtok_token_size).ret_expr
        r = self.state.se.If(self.state.se.Unconstrained('strtok_case', self.state.arch.bits) == 0, token_ptr,self.state.se.BVV(0, self.state.arch.bits))
        self.state.libc.strtok_heap.append(token_ptr)
        return r

self_dict = {
    "_setbuf":hook_setbuf(),
    "_alarm":hook_alarm(),
    "_strtok":hook_strtok()
}

func_dict = {
    "_IO_puts":"puts",
    "___strtol":"strtol",
    "fputc":"putchar",
    "_IO_ungetc":"ungetc",
    "__IO_vfprintf_internal":"printf",
    "_IO_fwrite":"fwrite",
    "_atoi":"atoi",
    "__IO_vsprintf":"sprintf",
    "_strlen":"strlen",
    "_memcpy":"memcpy",
    "_IO_fread":"fread",
    "_getchar":"getchar",
    "__IO_vfscanf_internal":"scanf",
    "___libc_system":"system",
    "___snprintf":"snprintf",
    "__IO_feof":"feof",
    "__IO_putc":"putc",
    "__IO_getc":"fgetc"
}

# in func_dict, there may be mistacks like lack of _. Check every challenge again. 

kernel_dict = {
    "___libc_read":"read",
    "___libc_write":"write",
    "_time":"time"
}

glibc_dict = {
    "___libc_start_main":"__libc_start_main"
}

posix_dict = {
    "___strdup":"strdup"
}


# util for get func details, analyser

def get_func_details(func_detail_a_path):
    f = open(func_detail_a_path, 'r')
    func_details = pickle.load(f)
    f.close()

    hook_table = {}
    for ea, (func_name, is_lib, end_addr) in func_details.items():
        if is_lib != 0:
            if func_dict.has_key(func_name):
                tar_func = func_dict[func_name]
                hook_table[ea] = angr.SIM_PROCEDURES['libc'][tar_func]()
            elif self_dict.has_key(func_name):
                hook_table[ea] = self_dict[func_name]
            elif kernel_dict.has_key(func_name):
                tar_func = kernel_dict[func_name]
                hook_table[ea] = angr.SIM_PROCEDURES['linux_kernel'][tar_func]()
            elif posix_dict.has_key(func_name):
                tar_func = posix_dict[func_name]
                hook_table[ea] = angr.SIM_PROCEDURES['posix'][tar_func]()
            elif glibc_dict.has_key(func_name):
                tar_func = glibc_dict[func_name]
                hook_table[ea] = angr.SIM_PROCEDURES['glibc'][tar_func]()
        else:
            continue
    return hook_table


# this is for running with bash timeout
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Driller local callback")
    parser.add_argument('binary_path')
    parser.add_argument('fuzzer_out_dir')
    parser.add_argument('bitmap_path')
    parser.add_argument('path_to_input_to_drill')
    parser.add_argument('--length-extension', help="Try extending inputs to driller by this many bytes", type=int)

    args = parser.parse_args()

    logcfg_file = os.path.join(os.getcwd(), '.driller.ini')
    if os.path.isfile(logcfg_file):
        logging.config.fileConfig(logcfg_file)

    binary_path, fuzzer_out_dir, bitmap_path, path_to_input_to_drill = sys.argv[1:5]

    fuzzer_bitmap = open(args.bitmap_path, "r").read()

    # go to default folder(same to dict path) and check "binname_func_details"
    hooker = {}
    func_detail_a_path = os.path.basename(binary_path) + "_func_details"
    l.warning("File: %s." % func_detail_a_path)
    if os.path.isfile(func_detail_a_path):
        l.warning("Using Func Details: %s", func_detail_a_path)
        hooker = get_func_details(func_detail_a_path)

    l.warning("Hooker: %s." % hooker)

    # create a folder
    driller_dir = os.path.join(args.fuzzer_out_dir, "driller")
    driller_queue_dir = os.path.join(driller_dir, "queue")
    try: os.mkdir(driller_dir)
    except OSError: pass
    try: os.mkdir(driller_queue_dir)
    except OSError: pass

    l.debug('drilling %s', path_to_input_to_drill)
    # get the input
    inputs_to_drill = [open(args.path_to_input_to_drill, "r").read()]
    if args.length_extension:
        inputs_to_drill.append(inputs_to_drill[0] + '\0' * args.length_extension)

    for input_to_drill in inputs_to_drill:
        l.warning("Calling Driller@%s, %s" % (args.binary_path, input_to_drill))

        # add hook arg here
        d = driller.Driller(args.binary_path, input_to_drill, fuzzer_bitmap, hooks = hooker)
        count = 0
        l.warning("Generating: ")
        for new_input in d.drill_generator():
            id_num = len(os.listdir(driller_queue_dir))
            fuzzer_from = args.path_to_input_to_drill.split("sync/")[1].split("/")[0] + args.path_to_input_to_drill.split("id:")[1].split(",")[0]
            filepath = "id:" + ("%d" % id_num).rjust(6, "0") + ",from:" + fuzzer_from
            filepath = os.path.join(driller_queue_dir, filepath)
            with open(filepath, "wb") as f:
                f.write(new_input[1])
            l.warning("%d : %s" %(count, new_input[1]))
            count += 1
        l.warning("found %d new inputs", count)
