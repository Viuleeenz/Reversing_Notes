var ptr_WSAStartup = Module.getExportByName(null,"WSAStartup");
var counter = 0;
var PROTECTION = 'wr-';

function writeBufferToFile(filename, buffer){
	let file = new File(filename, 'wb');
	file.write(buffer);
	file.flush();
	file.close();
}

function dumpProcessMemory(protection) {
	let ranges = Process.enumerateRanges(protection);
	console.log('[BEGIN] Memory ranges located: ' + ranges.length );
	ranges.forEach(function (range) {
		let destFileName = `dumps/${range.base}_dump`;
		let arrayBuffer = null;

		try {
			arrayBuffer = range.base.readByteArray(range.size);
		}
		catch(e){
			console.log('[ERROR] Dumping memory at: ' + range.base);
		}

		if (arrayBuffer){
			writeBufferToFile(destFileName,arrayBuffer);
		}
	});

}

Interceptor.attach(ptr_WSAStartup,
{
	onEnter: function (args)
	{
		counter = counter + 1;
		if (counter == 2){
			let ranges = Process.enumerateRanges(PROTECTION);
			console.log('[BEGIN] Memory ranges located: ' + ranges.length );
			ranges.forEach(function (range) {
				let destFileName = `dumps/${range.base}_dump`;
				let arrayBuffer = null;
				try {
					arrayBuffer = range.base.readByteArray(range.size);
				}
				catch(e){
					console.log('[ERROR] Dumping memory at: ' + range.base);
				}

				if (arrayBuffer){
					let file = new File(destFileName, 'wb');
					file.write(arrayBuffer);
					file.flush();
					file.close();
				}
			});
			console.log('[END] Memory dumped correctly');
		}

	},

	onLeave: function (retvals)
	{
		
	}
});
