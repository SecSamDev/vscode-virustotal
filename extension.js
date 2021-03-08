const vscode = require('vscode');
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const {VirusTotalQueue} = require('./src/main')
const {openDatabase} = require('./src/cache')
// this method is called when your extension is activated
// your extension is activated the very first time the command is executed

/**
 * @param {vscode.ExtensionContext} context
 */
async function activate(context) {


	let extension_config = vscode.workspace.getConfiguration("virustotal");

	let cache_location = extension_config.get("database_path")
	if (!cache_location) {
		cache_location = await select_cache_location()
		extension_config.update("database_path", cache_location, vscode.ConfigurationTarget.Global, true)
	}

	let api_key = extension_config.get("api_key")
	if (!api_key) {
		api_key = await vscode.window.showInputBox({
			prompt: "VirusTotal Api-Key"
		})
		extension_config.update("api_key", api_key, vscode.ConfigurationTarget.Global, true)
	}
	let remove_engine_info = extension_config.get("remove_engine_info")
	let shared_folder = extension_config.get("shared_folder")

	if (!shared_folder) {
		shared_folder = await vscode.window.showQuickPick(["Use a shared folder to perform cooperative tasks?", "No thanks"], { canPickMany: false })
		if (shared_folder != "No thanks") {
			let shared_path = (await vscode.window.showOpenDialog({ canSelectFolders: true, canSelectFiles: false, canSelectMany: false, title: "Select a valid location for the cache database" }))[0].fsPath
			if (fs.existsSync(shared_path)) {
				extension_config.update("shared_folder", shared_path, vscode.ConfigurationTarget.Global, true)
				//Check if it has folders
				if (!fs.existsSync(path.join(shared_path, "processed_files"))) {
					//Create folders
					fs.mkdirSync(path.join(shared_path, "processed_files"));
					fs.mkdirSync(path.join(shared_path, "to_process"));
					fs.mkdirSync(path.join(shared_path, "shared_db"));
				}
			}
		} else {
			extension_config.update("shared_folder", "-", vscode.ConfigurationTarget.Global, true)
		}
	}
	let db = await openDatabase(path.join(cache_location,"ioc_list.db"))
	let VT_CACHE = new VirusTotalQueue(api_key,db, {
		remove_engine_info
	})

	// The command has been defined in the package.json file
	// Now provide the implementation of the command with  registerCommand
	// The commandId parameter must match the command field in package.json
	let disposable = vscode.commands.registerCommand('virustotal.analyze_data', async function () {
		let data = await vscode.window.showInputBox({
			prompt: "IP, Hash or Domain to analyze?"
		})
		if(!data){
			return;
		}
		let ioc = VT_CACHE.analyze_data(data, async (resp) => {
			let doc = await vscode.workspace.openTextDocument({
				language : "json",
				content :JSON.stringify(resp["data"],null,"\t")
			});
			await vscode.window.showTextDocument(doc)
		})
		if(!ioc){
			vscode.window.showInformationMessage(`VirusTotal is analyzing ${data}`);
		}

	});
	context.subscriptions.push(disposable);

	disposable = vscode.commands.registerCommand('virustotal.analyze_iocs', async function (file_name) {
		let content = fs.readFileSync(file_name.fsPath,"utf-8")
		let lines = content.split("\n")
		let toReturn = "IOC\tHarmless\tMalicious\tSuspicious\tUndetected\tCountry\tISP\n"
		for(let ln of lines){
			let res = null
			try{
				res = VT_CACHE.analyze_data(ln);
			}catch(e){}

			if(res && res.data && res.data.attributes && res.data.attributes.last_analysis_stats) {
				let malicious = ""
				try {
					malicious = res.data.attributes.last_analysis_stats.harmless + "\t" + res.data.attributes.last_analysis_stats.malicious + "\t" + res.data.attributes.last_analysis_stats.suspicious + "\t" + res.data.attributes.last_analysis_stats.undetected + "\t" + res.data.attributes.country + "\t" + res.data.attributes.as_owner
				}catch(e){}
				toReturn += ln + "\t" + malicious + "\n"
			}else{
				toReturn += ln + "\tN/A\n"
			}
		}
		let doc = await vscode.workspace.openTextDocument({
			language : "json",
			content : toReturn
		});
		await vscode.window.showTextDocument(doc)

		vscode.window.showInformationMessage(`VirusTotal is analyzing IOCs in ${path.basename(file_name.fsPath)}`);

	});
	context.subscriptions.push(disposable);

	disposable = vscode.commands.registerCommand('virustotal.analyze_file', async function (file_name) {
		
		let hash = await hash_sha1_file(file_name.fsPath)
		VT_CACHE.analyze_data(hash, async (resp) => {
			let doc = await vscode.workspace.openTextDocument({
				language : "json",
				content :JSON.stringify(resp["data"],null,"\t")
			});
			await vscode.window.showTextDocument(doc)
		})
		vscode.window.showInformationMessage(`VirusTotal is analyzing <${path.basename(file_name.fsPath)}> with hash <${hash}>`);
	});
	context.subscriptions.push(disposable);


	disposable = vscode.commands.registerCommand('virustotal.submit_file', async function (file_name) {
		
		let hash = await hash_sha1_file(file_name.fsPath)
		VT_CACHE.analyze_file(file_name.fsPath, async (resp) => {
			let doc = await vscode.workspace.openTextDocument({
				language : "json",
				content :JSON.stringify(resp["data"],null,"\t")
			});
			await vscode.window.showTextDocument(doc)
		})
		vscode.window.showInformationMessage(`The file <${path.basename(file_name.fsPath)}> with hash <${hash}> has been submited to VirusTotal`);
	});
	context.subscriptions.push(disposable);

	disposable = vscode.commands.registerCommand('virustotal.analyze_text', async function (opts) {
		
		var data = vscode.window.activeTextEditor.document.getText(vscode.window.activeTextEditor.selection);
		if(!data || data.length == 0){
			return;
		}
		let ioc = VT_CACHE.analyze_data(data, async (resp) => {
			let doc = await vscode.workspace.openTextDocument({
				language : "json",
				content :JSON.stringify(resp["data"],null,"\t")
			});
			await vscode.window.showTextDocument(doc)
		});
		if(!ioc){
			vscode.window.showInformationMessage(`VirusTotal is analyzing ${data}`);
		}
	});
	context.subscriptions.push(disposable);
	disposable = vscode.commands.registerCommand('virustotal.import_database', async function (file_name) {
		let database_content = JSON.parse(fs.readFileSync(file_name.fsPath,{encoding: "utf-8"}))

		try{
			VT_CACHE.import_database(database_content)
			vscode.window.showInformationMessage(`Database suscesfully imported`);
		}catch(e){
			vscode.window.showErrorMessage(`Error importing database ${file_name.fsPath}`);
		}
		
		
	});
	context.subscriptions.push(disposable);
	
}

// this method is called when your extension is deactivated
function deactivate() { }

module.exports = {
	activate,
	deactivate
}


async function select_cache_location() {
	return (await vscode.window.showOpenDialog({ canSelectFolders: true, canSelectFiles: false, canSelectMany: false, title: "Select a valid location for the cache database" }))[0].fsPath
}

async function hash_sha1_file(file_path) {
	return new Promise((resolve, reject) => {
		let hash = crypto.createHash("sha1")
		const input = fs.createReadStream(file_path);
		input.on('data', function(data) {
			hash.update(data)
		})
		input.on('end', () => {
			resolve(hash.digest('hex'))
		})
		input.on('error', (e) => {
			reject(e)
		})
	})
}