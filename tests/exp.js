var fuzz = require("../fuzz");
var config = require("../fuzz/config.js");
config.MAP_SIZE = 128;
//fuzz.manual_loop_start = true;

var className = "tw.almor.lib.security.SecurityTool"

fuzz.target_module = "libAlmorSecurity.so";

function describeJavaClass(className) {
    var methods = Java.use(className).class.getDeclaredMethods()
    methods.forEach(method=>{
        if(method.toString().includes("native")){
            //console.log(method);
            console.log("Method name :" + method.getName());
            console.log("Method parameter : " + method.getParameterTypes())
            console.log("Method return Type : " + method.getReturnType())
        }
    })
    
    
}
console.log("[+]>Start fuzzing..")


fuzz.fuzzer_test_one_input = function(payload){
    Java.perform(function(){
        var targetClass = Java.use(className)
       // console.log("[+]>Found class:" + targetClass)
        var test_func = targetClass.nativeVerify.overload("[B", "[B", "[B", "[B").clone({ traps: 'all' });   
        //test_func = targetClass.nativeSign.overload("[B", "[B", "[B").clone({ traps: 'all' });
        test_func.call(targetClass, payload, payload, payload, payload);
    })
   
}
    
//fuzz.fuzzing_loop();
