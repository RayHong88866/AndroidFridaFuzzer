var fuzz = require("../fuzz");
var config = require("../fuzz/config.js");
config.MAP_SIZE = 128;
//fuzz.manual_loop_start = true;

var className = "tw.almor.lib.security.SecurityTool"

fuzz.target_module = "libAlmorSecurity.so";

function describeJavaClass(className, methodName) {
    var methods = Java.use(className).class.getDeclaredMethods()
    var retVal = [];
    methods.forEach(method=>{
        if(method.toString().includes(methodName)){
            retVal.push(method)
            
        }
    })
    return retVal
    
}


console.log("[+]>Start fuzzing..")

fuzz.fuzzer_test_one_input = function(payload){
    Java.perform(function(){
        var targetClass = Java.use(className)
        //var nativeSign = targetClass.nativeSign.overload("[B", "[B", "[B").clone({ traps: 'all' });
        var nativeAESDecryptFile = targetClass.nativeAESDecryptFile.overload("[B", "[B", "[B", "[B").clone({ traps: 'all' });
        nativeAESDecryptFile.call(targetClass , payload, payload, payload, payload)
    })
}


/*fuzz.init_callback = function () {
    Java.perform(function(){
        var methods = describeJavaClass(className, "native")

        var targetClass = Java.use(className)
 
   
        var methodNames =[]
        methods.forEach(method=>{
            if(!methodNames.includes(method.getName())){
                methodNames.push(method.getName())
            }           
        });
        var index = 1
        methodNames.forEach(name=>{
           
            targetClass[name].overloads.forEach(target=>{
                var len = target.argumentTypes.length
                var types=[]
                for(var i =0; i<len;i++){
                    types.push(target.argumentTypes[i].className)
                }
                console.log("[+]"+index+"."+name+ " "+types)
                index = index+1
            })
        })
        process.stdout.write("input> ");
        process.stdin.setEncoding('utf8');
        process.stdin.once('data', function(val){
            console.log(val)
        }).resume();
        fuzz.fuzzer_test_one_input = function(payload){

            var test_func = target.clone({traps: 'all' });
            switch(4){
                case 1:
                    test_func.call(targetClass, payload);        
                    break;   
                case 2:
                    test_func.call(targetClass, payload, payload);
                    break;
                case 3:
                    test_func.call(targetClass, payload, payload, payload);    
                    break;           
                case 4:
                    test_func.call(targetClass, payload, payload, payload, payload);     
                    break;           
                case 5:
                    test_func.call(targetClass, payload, payload, payload, payload, payload);
                    break;
            } 
        }
       // console.log("[+]>Found class:" + targetClass)
        
        //test_func = targetClass.nativeSign.overload("[B", "[B", "[B").clone({ traps: 'all' });
        
    })
}*/

    
//fuzz.fuzzing_loop();
