var ptr_VirtualProtectAddress = Module.getExportByName(null,"VirtualProtect");
Interceptor.attach(ptr_VirtualProtectAddress,
{
	onEnter: function (args)
	{
		var lpAddress = args[0];
		var vSize = args[1].toInt32();
		var nProtect = args[2];
		
		// check for MZ signature
		if (lpAddress.readAnsiString(2) == "MZ")
		{
			console.log("[+]Found an MZ!");
			console.log("[+] VirtualProtect hooked: \n \
				Size: " + vSize + "\n \
				Address: " + lpAddress + "\n \
				Protection: " + nProtect +"\n" );
			
			/* 
			if module != null we are in the main module 
			and because of Ursnif code manipulation, 
			that module do not contains the actual  
			payload.
			*/
			
			if (Process.findModuleByAddress(lpAddress) == null )
			{
			var module = Process.findRangeByAddress(lpAddress);
			console.log("[+] Oh Wow! Interesting module discovered... \n \
			 Module Base Address: " + module.base + "\n \
			 Module Size: " + module.size );
			
			// lpAddress point to the same address of module.base
			var exeContent = lpAddress.readByteArray(module.size);

			//write bin file
			var filename = lpAddress + "_mz.bin";
			var file = new File(filename, "wb");
			file.write(exeContent);
			file.flush();
			file.close();
			
			console.log(" [+] Dumped filename: " + filename);
			
			}
			
		}

	},

	onLeave: function (retvals)
	{
		
	}
});
