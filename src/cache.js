const {Loki} = require('@lokidb/loki')
const {FSStorage} = require('@lokidb/fs-storage')

async function openDatabase(location){
    const loki = new Loki(location,{
        serializationMethod :'normal',
        env : 'NODEJS',
    });
    FSStorage.register()
    let adapter = new FSStorage()
    
    await loki.initializePersistence({
        adapter,
        autoload : true,
        autosave : true,
        autosaveInterval : 15000,
        throttledSaves : true,
        persistenceMethod : 'fs-storage',
    })
    let collection_common = loki.getCollection("data")
    if(collection_common == null) {
        collection_common = loki.addCollection("data",{unique : ["ioc"]})
    }
    let collection_queue = loki.getCollection("queue")
    if(collection_queue == null) {
        collection_queue = loki.addCollection("queue",{unique : ["ioc"]})
    }
    let collection_stats = loki.getCollection("stats")
    if(collection_stats == null) {
        collection_stats = loki.addCollection("stats",{unique : ["day"]})
    }
    return loki
}

module.exports.openDatabase = openDatabase