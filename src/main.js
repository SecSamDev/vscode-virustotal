const vt = require('./vt')
const net = require('net')
const vscode = require('vscode')
const { Loki } = require("@lokidb/loki")

const IS_DOMAIN = new RegExp("(\\w+\\.)+\\w+", "i");
const IS_HASH = new RegExp("[a-f0-9]+", "i");

class VirusTotalQueue {
    /**
     * 
     * @param {string} api_key 
     * @param {Loki} database 
     * @param {{remove_engine_info : bool}} options
     */
    constructor(api_key, database, options) {
        this.api_key = api_key
        this.database = database
        this.queue_files = []
        this.queue_data = []
        this.local_cache = this.database.getCollection("data")
        this.queue = this.database.getCollection("queue")
        this.stats = this.database.getCollection("stats")
        this.remove_engine_info = options?.remove_engine_info || false

        let elements = this.queue.find()
        this.queue_data = elements
        this.last_check = 0;
        let current_day = currentDay()

        let updates_today = this.stats.findOne({ "day": current_day })
        this.updates_today = 0
        if (!updates_today) {
            this.stats.insertOne({ "day": current_day, "inserts": 0 })
        } else {
            this.updates_today = updates_today.inserts
        }

        this.subscriptions = {}


        // VT Free API = 4 req/minute = 1 / 15 secs
        let that = this;
        this.timer = setInterval(async () => {
            let nw = Date.now()
            if ((that.last_check + 15000) > nw) {
                return
            }
            if (that.updates_today > 500) { // VT limit for today
                return
            }

            let file_to_analyze = that.queue_files.shift();
            let request_done = false
            if (!!file_to_analyze) {
                try {
                    request_done = true
                    let resp = await vt.analyze_file(that.api_key, file_to_analyze)

                    if(resp.data && resp.data.type == "analysis"){
                        await vscode.window.showWarningMessage("Analysis in progress: " + resp.data.id)
                    }
                } catch (e) {
                    await vscode.window.showWarningMessage("Could not send file \n" + e.toString())
                }
            } else {
                let obj = that.queue_data.shift();
                if (!!obj) {
                    try {
                        obj.ioc = obj.ioc.trim()
                        let resp = null
                        that.last_check = nw;
                        if (obj.type == "ip") {
                            resp = await vt.analyze_ip(that.api_key, obj.ioc)
                        } else if (obj.type == "domain") {
                            resp = await vt.analyze_domains(that.api_key, obj.ioc)
                        } else if (obj.type == "hash") {
                            resp = await vt.analyze_hash(that.api_key, obj.ioc)
                        }
                        request_done = true
                        if (!resp) {
                            await vscode.window.showWarningMessage("Something went wrong with " + obj.ioc)
                        } else {
                            that.queue.findAndRemove({ "ioc": obj.ioc })
                            if (that.remove_engine_info) {
                                if (resp.data && resp.data.attributes && resp.data.attributes.last_analysis_results) {
                                    delete resp.data.attributes.last_analysis_results
                                }
                            }
                            resp.ioc = obj.ioc
                            resp.processed_time = Date.now()
                            that.local_cache.insertOne(resp)
                            try {
                                that.subscriptions[obj.ioc](resp)
                            } catch (e) { }

                        }
                    } catch (e) {
                        if (e.message.includes("StatusCode: 404")) {
                            try {
                                that.subscriptions[obj.ioc]({
                                    "data": {
                                        "error": "IOC not present in VirusTotal " + obj.ioc,
                                        "instructions": "If you need to submit the file, please try the option 'Submit File to VirusTotal'"
                                    }

                                })
                            } catch (e) {}
                            try{
                                that.queue.findAndRemove({ "ioc": obj.ioc })
                            }catch(e){
                                console.log(e)
                            }
                        } else {
                            that.queue_data.push(obj)
                        }

                    }

                }
            }
            if(request_done){
                that.stats.findAndUpdate({ "day": currentDay() }, (obj) => {
                    obj.inserts += 1
                    return obj
                })
                let update = that.stats.findOne({ "day": currentDay() })
                try {
                    await that.database.saveDatabase()
                } catch (e) { }
                that.updates_today = update.inserts
                
            }
            that.last_check = nw;
            
        }, 1000)
    }

    subscribe(ioc, fn) {
        this.subscriptions[ioc] = fn
    }
    is_in_queue(data) {
        return !!this.queue.findOne({ "ioc": data })
    }
    is_alredy_processed(data) {
        return !!this.local_cache.findOne({ "id": data })
    }

    /**
     * 
     * @param {string} data 
     * @param {Function} fn 
     * @returns 
     */
    analyze_data(data, fn) {
        data = data.trim()
        let cached_element = this.local_cache.findOne({ "ioc": data })
        let now = Date.now();

        if (!!cached_element && cached_element.processed_time && (cached_element.processed_time + 2629800000) > now) {
            if (fn) {
                fn(cached_element)
            }
            return cached_element
        }
        if (net.isIP(data) != 0) {
            if(data.startsWith("10.") || data.startsWith("192.168.") ){
                return null
            }
            if(data.startsWith("172.")){
                let n_2 = data.split(".")[1]
                if(n_2 >= 16 && n_2 <= 31){
                    return null
                }
            }

            this.queue.insertOne({ "type": "ip", "ioc": data })
            this.queue_data.push({ "type": "ip", "ioc": data })
        } else if ([32, 40, 64].includes(data.length) && IS_HASH.test(data)) {
            this.queue.insertOne({ "type": "hash", "ioc": data })
            this.queue_data.push({ "type": "hash", "ioc": data })
        } else if (IS_DOMAIN.test(data)) {
            this.queue.insertOne({ "type": "domain", "ioc": data })
            this.queue_data.push({ "type": "domain", "ioc": data })
        } else {
            throw new Error("Invalid IOC type")
        }
        if (fn) {
            this.subscribe(data, fn)
        }
        return null
    }
    analyze_file(file_path, fn) {
        this.queue_files.push(file_path)
        if (fn) {
            this.subscribe(data, fn)
        }
    }
    import_munin_database(database){
        for(let element of database) {
            try {
                element["ioc"] = element["id"]
                this.local_cache.insertOne(element)
            }catch(e){}
        }
    }
    import_database(database){
        let data_collection = database._collections.find(vl => vl.name == "data")
        for(let element of data_collection._data) {
            if (this.remove_engine_info) {
                if (element.data && element.data.attributes && element.data.attributes.last_analysis_results) {
                    delete element.data.attributes.last_analysis_results
                }
            }
            try {
                this.local_cache.insertOne(element)
            }catch(e){}
        }
    }
    show_queue_iocs(){
        try{
            return this.queue.find().map(val => val.ioc)
        }catch(e){
            return []
        }
    }
    show_last_inserted_items(){
        try{
            return this.local_cache.find().map(val => val.ioc)
        }catch(e){
            return []
        }
    }
}

function currentDay() {
    let date_ob = new Date(Date.now());
    let date = date_ob.getDate();
    let month = date_ob.getMonth() + 1;
    let year = date_ob.getFullYear();
    return year + "-" + month + "-" + date

}

module.exports.VirusTotalQueue = VirusTotalQueue