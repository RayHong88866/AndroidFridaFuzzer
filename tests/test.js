

var className = "tw.almor.lib.security.SecurityTool"

//fuzz.target_module = "libAlmorSecurity.so";

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

function str2bytesArray(str){
    var bytes = []; // char codes

    for (var i = 0; i < str.length; ++i) {
        var charCode = str.charCodeAt(i);
        //bytes.push((charCode & 0xFF00) >> 8);
        bytes.push(charCode & 0xFF);
    }

    return bytes
}
function typeConvert(str, payload){
    if(str[0] =="["){
        if(str[1]=="B"){
            return payload
        }
    }

}

function main(){
    Java.perform(function(){
        var env = Java.vm.getEnv()
        var methods = describeJavaClass(className, "native")
        //console.log(className.replace(".","/"))
        var targetClass = Java.use(className)
 
        //var f = env.staticVaMethod()
        var methodNames =[]
        methods.forEach(method=>{
            if(!methodNames.includes(method.getName())){
                methodNames.push(method.getName())
            }           
        });
        //console.log(methodNames)
        methodNames.forEach(name=>{
            console.log(name)
            targetClass[name].overloads.forEach(target=>{
                var len = target.argumentTypes.length
                var types=[]
                for(var i =0; i<len;i++){
                    types.push(target.argumentTypes[i].className)
                }
                console.log(target.clone({traps: 'all' }));
                
            })
        })
            //console.log(mn.getName())
            //for(target in targetClass[name].overloads){
            //    console.log(target)
            //}
            
            //console.log(targetClass[method.getName()].overloads[0].argumentTypes[0].className)
        
       /* for(var i=0; i<=60000; i++){
            var test_func = targetClass.nativeEncrypt.overload("[B","[B","[B","[B").clone({ traps: 'all' });
            test_func.call(targetClass, str2bytesArray("a"), str2bytesArray("a"), str2bytesArray("a"), str2bytesArray("a"))
            console.log(i)
        }*/
    //var test_func = targetClass.encrypt.overload("java.lang.String", "java.lang.String").clone({ traps: 'all' });
    //var test_func = targetClass.nativeEncrypt.overload("[B"), "[B").clone({ traps: 'all' });
    //    var test_func = targetClass.nativeEncrypt.overload("[B", "[B")
    //    console.log(test_func.call(targetClass, [0x64, 0x64, 0x64, 0x64 ], [0x64, 0x64, 0x64, 0x64 ]))
     

    })
}
setImmediate(main)
//console.log(targetClass)
//describeJavaClass(className ,"native")


/*console.log(targetClass)
var para_type = describeJavaClass(className, "nativeEncrypt")
console.log(para_type)*/

//console.log(str2bytesArray("a".repeat(0x11e3)).slice(0x11e3-1))

//fuzz.fuzzer_test_one_input = function(payload){

//var str = fuzz.utils.uint8arr_to_str(payload);
//console.log("[+]Payload >> "+str)
//console.log(test_func.call(targetClass, [0x64, 0x64, 0x64, 0x64 ], [0x64, 0x64, 0x64, 0x64 ]));
//}

//
//fuzz.fuzzing_loop();
    


//console.log (" >> Agent loaded!");