const http = require('http');
function compute() {
    let sum = 0;
    for(let i = 0; i < 10000000; i++) {
        sum += i;
    }
}
setInterval(() => {
    compute();
    setImmediate(() => {
        compute();
    });
}, 10000)
// http.createServer((req, res) => {
   
//     compute()
//     res.end("ok");
// }).listen(8000);
console.log(process.pid);