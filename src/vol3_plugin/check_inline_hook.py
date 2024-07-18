import capstone
from volatility3.framework import automagic, constants, interfaces, plugins, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from volatility3.plugins.linux import check_syscall

class Check_inline_hook(interfaces.plugins.PluginInterface):
    _version = (1, 0, 0)
    _required_framework_version = (2, 7, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.vmlinux = self.context.modules[self.config["kernel"]]

        self.ptr_sz = self.vmlinux.get_type("pointer").size
        
        if self.ptr_sz == 4:
            mode = capstone.CS_MODE_32
        else:
            mode = capstone.CS_MODE_64

        self.md = capstone.Cs(capstone.CS_ARCH_X86, mode)


    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            )
        ]
    
    def check_trampoline(self, addr):
        vmlinux = self.vmlinux
        ptr_sz = self.ptr_sz
        md = self.md

        data = self.context.layers.read(vmlinux.layer_name, addr, 5)
  
        if (ptr_sz ==4 or data != bytes.fromhex("0f1f440000")):
            for address, size, mnemonic, op_str in md.disasm_lite(data, addr):
                if mnemonic == "call" or mnemonic == "jmp":
                    target_addr = int(op_str, 16)
                    syms = list(vmlinux.get_symbols_by_absolute_location(target_addr))
                    if len(syms)>0:
                        name = syms[0].split(constants.BANG)[1]
                        target = op_str + "(" + name + ")"
                    else:
                        name ="UNKNOWN"
                        target = op_str

                    yield (mnemonic, target, address - addr, "In the trampoline, probably (eBPF) kprobe/ftrace.")

                elif mnemonic == 'int3':
                    yield (mnemonic, "UNKNOWN", address - addr, "In the trampoline, probably (eBPF) kprobe.")
                
                elif mnemonic == "ret":
                    yield (mnemonic, "UNKNOWN", address - addr, "In the trampoline.")

    # def check_inline_hook(self, addr):
    #     vmlinux = self.vmlinux
    #     ptr_sz = self.ptr_sz
    #     md = self.md

    #     data = self.context.layers.read(vmlinux.layer_name, addr, 512)
  
    #     if (ptr_sz ==4 or data != bytes.fromhex("0f1f440000")):
    #         for address, size, mnemonic, op_str in md.disasm_lite(data, addr):
    #             syms = list(vmlinux.get_symbols_by_absolute_location(address))
    #             if len(syms)>0:
    #                 sn = syms[0].split(constants.BANG)[1]
    #             else:
    #                 sn ="     "

    #             if mnemonic == "call" or mnemonic[0] == 'j':
    #                 target = int(op_str, 16)
    #                 syms = list(vmlinux.get_symbols_by_absolute_location(target))
    #                 if len(syms)>0:
    #                     name = syms[0].split(constants.BANG)[1]
    #                 else:
    #                     name ="UNKNOWN"

    #                 op_str += " (" + name +")"

    #             print(sn + " " + f'{address:#x}' + " " + mnemonic + " " + op_str)

    def _check_syscall_functions(self):
        vmlinux = self.vmlinux

        automagics = automagic.choose_automagic(automagic.available(self._context), check_syscall.Check_syscall)
        plugin = plugins.construct_plugin(self.context, automagics, check_syscall.Check_syscall, self.config_path,
                            self._progress_callback, self.open)

        for _, syscall in plugin._generator():
            _, _, index, handler_addr, handler_sym = syscall

            if handler_sym.endswith("sys_ni_syscall") or handler_sym == "UNKNOWN":
                continue

            for type, target, offset, note in self.check_trampoline(handler_addr):
                yield ("Syscall", handler_sym, format_hints.Hex(handler_addr), type, target, format_hints.Hex(offset), note)
        
        # functions = ["do_syscall_64", "syscall_enter_from_user_mode", "x64_sys_call", "syscall_exit_to_user_mode"]

        # for func in functions:
        #     if vmlinux.has_symbol(func):
        #         print(func + ":")

        #         addr = vmlinux.get_absolute_symbol_address(func)

        #         self.check_inline_hook(addr)
        #     else:
        #         print("Cannot find "+func)

    
    def _generator(self):
        check_functions = [self._check_syscall_functions]

        for check_function in check_functions:
            for result in check_function():
                yield (0, result)

    def run(self):
        

        return renderers.TreeGrid(
            [
                ("Function Type", str),
                ("Function Name", str),
                ("Function Address", format_hints.Hex),
                ("Hook Type", str),
                ("Target Address", str),
                ("Instruction Offset",  format_hints.Hex),
                ("Note", str)
            ],
            self._generator()
        )

