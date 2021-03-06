const qbdi = require('/home/ray/usr/share/qbdiX86_64/frida-qbdi.js')
var fuzz = require("../fuzz");
qbdi.import();

var vm = new QBDI();
var TARGET_MODULE = "libAlmorSecurity.so"
Module.ensureInitialized(TARGET_MODULE);
var className = "tw.almor.lib.security.SecurityTool"
var targetClass = Java.use({name: className}) ;
var test_func = targetClass.encrypt.overload("java.lang.String", "java.lang.String").clone({ traps: 'all' });

function processJniOnLoad(libraryName) {
    const funcSym = "JNI_OnLoad";
    const funcPtr = Module.findExportByName(libraryName, funcSym);
    var JNI_OnLoad = new NativeFunction(funcPtr, "long", ["pointer", "pointer"])
    console.log("[+] Replacing " + funcSym + "() @ " + funcPtr + "...");
    // jint JNI_OnLoad(JavaVM *vm, void *reserved);
    var replacement = Interceptor.replace(funcPtr, new NativeCallback(function (vm, reserved) {

        console.log("[+] " + funcSym + "(" + vm + ", " + reserved + ") called");
        Interceptor.revert(funcPtr); // revert to the genuine implementation
        Interceptor.flush(); // ensure changes have been actually committed
        var retVal = qbdiExec(this.context, funcPtr, funcSym, [vm, reserved], true);
        processJniOnLoad(libraryName, funcSym); // replace the implementation again for a potential call later on
        return retVal;
    }, "long", ["pointer", "pointer"]));
    JNI_OnLoad(Java.vm, Java.vm.getEnv())
}

function qbdiExec(ctx, funcPtr, funcSym, args, postSync) {
    var vm = new QBDI(); // create a QBDI VM
    var state = vm.getGPRState();
    state.synchronizeContext(ctx, SyncDirection.FRIDA_TO_QBDI); // set up QBDI's context
    var stack = vm.allocateVirtualStack(state, 0x10000); // allocate a virtual stack

    vm.addInstrumentedModuleFromAddr(funcPtr);

    var icbk = vm.newInstCallback(function (vm, gpr, fpr, data) {
        var inst = vm.getInstAnalysis();
        console.log("0x" + inst.address.toString(16) + " " + inst.disassembly);
        return VMAction.CONTINUE;
    });
    var iid = vm.addCodeCB(InstPosition.PREINST, icbk); // register pre-instruction callback

    var vcbk = vm.newVMCallback(function (vm, evt, gpr, fpr, data) {
        const module = Process.getModuleByAddress(evt.basicBlockStart);
        const offset = ptr(evt.basicBlockStart - module.base);
        if (evt.event & VMEvent.EXEC_TRANSFER_CALL) {
            console.warn(" -> transfer call to 0x" + evt.basicBlockStart.toString(16) + " (" + module.name + "@" + offset + ")");
        }
        if (evt.event & VMEvent.EXEC_TRANSFER_RETURN) {
            console.warn(" <- transfer return from 0x" + evt.basicBlockStart.toString(16) + " (" + module.name + "@" + offset + ")");
        }
        return VMAction.CONTINUE;
    });
    var vid = vm.addVMEventCB(VMEvent.EXEC_TRANSFER_CALL, vcbk); // register transfer callback
    var vid2 = vm.addVMEventCB(VMEvent.EXEC_TRANSFER_RETURN, vcbk); // register return callback

    const javavm = ptr(args[0]);
    const reserved = ptr(args[1]);

    console.log("[+] Executing " + funcSym + "(" + javavm + ", " + reserved + ") through QBDI...");
    vm.call(funcPtr, [javavm, reserved]);
    var retVal = state.getRegister(0); // x86 so return value is stored on $eax
    console.log("[+] " + funcSym + "() returned " + retVal);
    if (postSync) {
        state.synchronizeContext(ctx, SyncDirection.QBDI_TO_FRIDA);
    }
    return retVal;
}

