
const https = require('https')
const fs = require('fs')
const path = require('path')
const FormData = require('form-data');

async function analyze_ip(api_key, ip) {
    return request_json_get(api_key, "/api/v3/ip_addresses/" + ip)
}

async function analyze_hash(api_key, hash) {
    return request_json_get(api_key, "/api/v3/files/" + hash)
}
async function analyze_domains(api_key, domain) {
    return request_json_get(api_key, "/api/v3/files/" + domain)
}

async function analyze_file(api_key, file_path) {
  return new Promise((resolve, reject) => {
    let rd = fs.readFileSync(file_path);
    var form = new FormData();
    form.append('file', rd, {filename : path.basename(file_path)});
    let headers = form.getHeaders();
    headers["x-apikey"] = api_key
    const req = https.request({
        hostname: "www.virustotal.com",
        host: "www.virustotal.com",
        port: 443,
        path : "/api/v3/files",
        method: "POST",
        headers : headers
    }, (res) => {
        if(res.statusCode < 200 || res.statusCode > 299) {
            reject({
                "message" : "Failed get: " + path + " StatusCode: " + res.statusCode,
                "statusCode" : res.statusCode
            })
        }
        const body = []
        res.on('data', chunk => body.push(chunk));
        res.on('end', () => {
            try {
                resolve(JSON.parse(body.join('')))
            }catch(e) {
                reject(e)
            }
        })
    });
    form.pipe(req);
    req.on('error', (err) => {
        reject(err)
    });
}); 
}

module.exports.analyze_domains = analyze_domains
module.exports.analyze_hash = analyze_hash
module.exports.analyze_ip = analyze_ip
module.exports.analyze_file = analyze_file

function request_json_get(api_key,path) {
    return new Promise((resolve, reject) => {
        const req = https.request({
            hostname: "www.virustotal.com",
            host: "www.virustotal.com",
            port: 443,
            path,
            method: "GET",
            headers : {
                "x-apikey" : api_key
            }
        }, (res) => {
            if(res.statusCode < 200 || res.statusCode > 299) {
                reject(new Error("Failed get: " + path + " StatusCode: " + res.statusCode))
            }
            const body = []
            res.on('data', chunk => {
                body.push(chunk)
            });
            res.on('end', () => {
                try {
                    resolve(JSON.parse(body.join('')))
                }catch(e) {
                    reject(e)
                }
            })
        });
        req.setTimeout(5000)
        req.on('error', (err) => {
            reject(err)
        });
        req.end();
    }); 
}