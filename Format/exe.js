//Everything in the format reader must be defined as an object called format.
//This ensures that all data in the format reader is overwritten when loading in a new format.

format = {
  //The variable des stores the data signatures.

  des: [],

  //Signature lengths.

  sig: new dataType("Signature", Descriptor.String8),

  //Section array name.

  sec: new dataType("Section Name", Descriptor.String8),

  //DLL, or driver name.

  dllName: new dataType("DLL Name", Descriptor.String8),

  //DLL, or driver function name.

  funcName: new dataType("Method name", Descriptor.String8),

  //Node being scanned. Important to not accept any new commands till complete or we could corrupt the data buffer.

  scanNode: false,

  //Reserved data Fields.

  r1: new dataType("Reserved", Descriptor.Other),
  r2: new dataType("Reserved", Descriptor.Other),

  //32/64 bit application.

  is64bit: false,

  //The processor core instruction type that the code is intended to run on.

  coreType: 0,

  //The applications base address.

  baseAddress: 0,

  //Disassembly virtual address.

  disV: 0,

  //Multipliers used to load 64 bit values.

  s24:2**24,s32:2**32,s40:2**40,s48:2**48,s56:2**56,

  //IO stream must be in ready state before we can Initialize the applications setup information.

  load: function(r) { if(!r) { file.wait(this,"load"); return; } file.onRead(this, "scan"); file.seek(0); file.read(4096); },

  /*-------------------------------------------------------------------------------------------------------------------------
  Initialize the programs setup information.
  -------------------------------------------------------------------------------------------------------------------------*/

  scan: function()
  {
    //PE header location.

    var msDos = false, pe = file.tempD[0x3C]|(file.tempD[0x3D]<<8)|(file.tempD[0x3E]<<16)|(file.tempD[0x3F]<<24);

    //Check if PE header exists by signature.

    msDos = (file.tempD[pe]|(file.tempD[pe+1]<<8)|(file.tempD[pe+2]<<16)|(file.tempD[pe+3]<<24))!=0x4550;
    
    //The root node is the binary application.
    
    var root = new treeNode(file.name.substring(file.name.lastIndexOf("/")+1,file.name.length),[],true);

    //Header data.
    
    var hData = new treeNode("Header Data",[],msDos); root.add(hData);
    
    //The dos 2.0 header structure.

    this.des[0] = new Descriptor([
      this.sig, //2 bytes.
      new dataType("Last 512 bytes", Descriptor.LUInt16),
      new dataType("512 bytes in file", Descriptor.LUInt16),
      new dataType("Number of Relocation Entries", Descriptor.LUInt16),
      new dataType("Header size", Descriptor.LUInt16),
      new dataType("Minimum Memory", Descriptor.LUInt16),
      new dataType("Maximum Memory", Descriptor.LUInt16),
      new dataType("Initial SS relative to start of file", Descriptor.LUInt16),
      new dataType("Initial SP", Descriptor.LUInt16),
      new dataType("Checksum (unused)", Descriptor.LUInt16),
      new dataType("Initial IP", Descriptor.LUInt16),
      new dataType("Initial CS relative to start of file", Descriptor.LUInt16),
      new dataType("Relocations Offset", Descriptor.LUInt16),
      new dataType("Overlay Number", Descriptor.LUInt16),
      this.r1, //8 bytes.
      new dataType("ID", Descriptor.LUInt16),
      new dataType("INFO", Descriptor.LUInt16),
      this.r2, //20 bytes.
      new dataType("PE Header Location", Descriptor.LUInt32)
    ]);
    var mzSize=(file.tempD[8]<<4)|(file.tempD[9]<<12);

    //Add the dos header information node.

    var mzHeader = new treeNode("MZ Header",[5,0,mzSize,false],msDos); hData.add(mzHeader);
    
    //Add the MS-Dos header.
    
    mzHeader.add("DOS 2.0 Header.h", [0]); this.des[0].offset = 0; this.des[0].setEvent(this, "mzHeader");

    //Dos header relocations if any.

    var rel = file.tempD[6] | (file.tempD[7]<<8), relOff = file.tempD[24] | (file.tempD[25]<<8); if(rel > 0)
    {
      //Dos 2.0 relocation structure.

      this.des[1] = new Descriptor([this.dosRel = new arrayType("Rel",[
        new dataType("Segment", Descriptor.LUInt16),
        new dataType("Offset", Descriptor.LUInt16)
      ])]);

      //Add dos relocation node to dos header information.

      mzHeader.add("DOS Relocations.h", [4]); this.des[1].setEvent(this, "mzRel"); this.dosRel.length(rel); this.des[1].offset = relOff;
    }

    //Add ms-dos application entry point for disassembly.

    mzHeader.add("Program Start (Machine Code).h", [2,(file.tempD[20]|(file.tempD[21]<<8))+((file.tempD[22]<<4)|(file.tempD[23]<<12))]);

    //If it is an ms dos application the rest of the file is mapped into RAM memory after the Dos header.

    if(msDos){ pe = mzSize; file.addV(mzSize,file.size-mzSize,0,file.size-mzSize); }

    //Else read the new PE header and dump the dos application that exists between the PE header.

    else
    {
      //We skip the dos header and map what remains before the PE header.

      file.addV(mzSize,pe-mzSize,0,pe-mzSize);

      //The PE header structure.

      this.des[2] = new Descriptor([
        this.sig, //4 bytes.
        new dataType("Machine", Descriptor.LUInt16),
        new dataType("Number Of Sections", Descriptor.LUInt16),
        new dataType("Time Date Stamp", Descriptor.LUInt32),
        new dataType("Pointer To Symbol Table", Descriptor.LUInt32),
        new dataType("Number Of Symbols", Descriptor.LUInt32),
        new dataType("Size Of OP Header", Descriptor.LUInt16),
        new dataType("Characteristics", Descriptor.LUInt16)
      ]);

      //Add the PE header node.

      hData.add("PE Header.h",[8]); this.des[2].offset = pe; this.des[2].setEvent(this, "peHeader");

      //Core type and mappable sections to ram.

      var sections = file.tempD[pe+6]|(file.tempD[pe+7]<<8); this.coreType = file.tempD[pe+4]|(file.tempD[pe+5]<<8); pe += 24;

      //The OP header has two types that are nearly identical for 32-bit or 64-bit binaries.

      var op = file.tempD[pe]|(file.tempD[pe+1]<<8); if(op == 267 || (this.is64bit = op == 523))
      {
        var type = this.is64bit ? Descriptor.LUInt64 : Descriptor.LUInt32, desOp = [
          this.sig, //2 bytes.
          new dataType("Major Linker Version", Descriptor.UInt8),
          new dataType("Minor Linker Version", Descriptor.UInt8),
          new dataType("Size Of Code", Descriptor.LUInt32),
          new dataType("Size Of Initialized Data", Descriptor.LUInt32),
          new dataType("Size Of Uninitialized Data", Descriptor.LUInt32),
          new dataType("Start Of Code.", Descriptor.LUInt32),
          new dataType("Base Of Code", Descriptor.LUInt32),
          new dataType("Base Of Data", Descriptor.LUInt32), //Remove if 64 bit.
          new dataType("Base Address", type),
          new dataType("Section Alignment", Descriptor.LUInt32),
          new dataType("File Alignment", Descriptor.LUInt32),
          new dataType("Major Operating System Version", Descriptor.LUInt16),
          new dataType("Minor Operating System Version", Descriptor.LUInt16),
          new dataType("Major binary Version", Descriptor.LUInt16),
          new dataType("Minor binary Version", Descriptor.LUInt16),
          new dataType("Major Sub system Version", Descriptor.LUInt16),
          new dataType("Minor Sub system Version", Descriptor.LUInt16),
          new dataType("Win 32 Version Value", Descriptor.LUInt32),
          new dataType("Size Of binary", Descriptor.LUInt32),
          new dataType("Size Of Headers", Descriptor.LUInt32),
          new dataType("Check Sum", Descriptor.LUInt32),
          new dataType("Sub system", Descriptor.LUInt16),
          new dataType("Dll Characteristics", Descriptor.LUInt16),
          new dataType("Size Of Stack Reserve", type),
          new dataType("Size Of Stack Commit", type),
          new dataType("Size Of Heap Reserve", type),
          new dataType("Size Of Heap Commit", type),
          new dataType("Loader Flags", Descriptor.LUInt32),
          new dataType("Data Directory Array Size", Descriptor.LUInt32),
        ]; if(this.is64bit){ desOp.splice(8,1); }
        
        //Add the OP header node.

        hData.add("OP Header.h",[12]); this.des[3] = new Descriptor(desOp); this.des[3].offset = pe; this.des[3].setEvent(this, "opHeader");

        //Add the applications entry point.

        if(this.is64bit) { this.baseAddress = (file.tempD[pe+24]|(file.tempD[pe+25]<<8)|(file.tempD[pe+26]<<16))+(file.tempD[pe+27]*format.s24)+(file.tempD[pe+28]*format.s32)+(file.tempD[pe+29]*format.s40)+(file.tempD[pe+30]*format.s48)+(file.tempD[pe+31]*format.s56); }
        else { this.baseAddress = (file.tempD[pe+28]|(file.tempD[pe+29]<<8)|(file.tempD[pe+30]<<16))+(file.tempD[pe+31]<<24); }

        root.add("Program Start (Machine Code).h", [3,this.baseAddress + ((file.tempD[pe+16]|(file.tempD[pe+17]<<8)|(file.tempD[pe+18]<<16))+(file.tempD[pe+19]<<24))]);

        //The data directory array size is the last 4 bytes of the OP header.

        pe += this.is64bit ? 112 : 96; var ddrSize = file.tempD[pe-4]|(file.tempD[pe-3]<<8)|(file.tempD[pe-2]<<16)|(file.tempD[pe-1]<<24);

        //Data directory array structure.

        this.des[4] = new Descriptor([this.dataDir = new arrayType("Section",[
          new dataType("Virtual offset", Descriptor.LUInt32),
          new dataType("Size", Descriptor.LUInt32)
        ])]);

        //Add the data directory array node.

        hData.add("Data Directory Array.h",[16]); this.dataDir.length(ddrSize); this.des[4].offset = pe; this.des[4].setEvent(this, "dirArray");

        //Scan the data directory array.

        var types = ["function Export Table.h", "DLL Import Table.h", "Resource Files.h", "Exception Table.h", "Security Level Settings.h",
        "Relocations.h", "DEBUG TABLE.h", "Description/Architecture.h", "Machine Value.h", "Thread Storage Location.h", "Load System Configuration.h",
        "Import Table of Functions inside program.h", "Import Address Setup Table.h", "Delayed Import Table.h", "COM Runtime Descriptor.h"];
        
        for(var e = pe + (ddrSize << 3), i = 0, size = 0, loc = 0; pe < e; pe += 8, i++)
        {
          loc = file.tempD[pe]|(file.tempD[pe+1]<<8)|(file.tempD[pe+2]<<16)|(file.tempD[pe+3]<<24);
          size = file.tempD[pe+4]|(file.tempD[pe+5]<<8)|(file.tempD[pe+6]<<16)|(file.tempD[pe+7]<<24);
          if( size > 0 ) { root.add(types[i],[-(i+1),loc + this.baseAddress,size]); }
        }
        
        types = undefined; this.readSec =
        [
          this.readExport,this.readDLL,this.readRes,this.noReader,this.noReader,this.readRelocation,this.noReader,this.noReader,
          this.noReader,this.noReader,this.noReader,this.noReader,this.noReader,this.noReader,this.noReader,this.noReader
        ];

        //Application section map to virtual address space structure.

        this.des[5] = new Descriptor([this.sections = new arrayType("Section Array element",[
          this.sec, //8 bytes.
          new dataType("Section Size Loaded In Ram", Descriptor.LUInt32),
          new dataType("Where to Store Bytes in Ram", Descriptor.LUInt32),
          new dataType("Byte length to read from EXE file", Descriptor.LUInt32),
          new dataType("Position to Start Reading EXE", Descriptor.LUInt32),
          this.r1, //12 bytes.
          new dataType("Section flags", Descriptor.LUInt32)
        ])]);

        //Add the section array node.

        hData.add("Mapped SECTIONS TO RAM.h",[20]); this.sec.length(8); this.sections.length(sections); this.des[5].offset = pe; this.des[5].setEvent(this, "secArray");

        //Read and map the applications sections into virtual address space.
        
        for(var e = pe + (sections * 40), vSize = 0, vOff = 0, size = 0, off = 0, i = 0; pe < e; pe += 40, i++)
        {
          vSize = file.tempD[pe+8]|(file.tempD[pe+9]<<8)|(file.tempD[pe+10]<<16)|(file.tempD[pe+11]<<24);
          vOff = file.tempD[pe+12]|(file.tempD[pe+13]<<8)|(file.tempD[pe+14]<<16)|(file.tempD[pe+15]<<24);
          size = file.tempD[pe+16]|(file.tempD[pe+17]<<8)|(file.tempD[pe+18]<<16)|(file.tempD[pe+19]<<24);
          off = file.tempD[pe+20]|(file.tempD[pe+21]<<8)|(file.tempD[pe+22]<<16)|(file.tempD[pe+23]<<24);

          file.addV( off, size, vOff + this.baseAddress, vSize );
        }
      }
      else { this.des[3] = new Descriptor([]); this.des[3].offset = pe; this.des[3].setEvent(this, "badSig"); }
    }

    //Set the computed size of all the headers.

    hData.setArgs([9,0,pe,false]);

    //Reset data model.

    dModel.clear();

    //Show virtual address space.

    if( !virtual.visible ) { showH(true); }

    //Set tree node event Handler.
    
    Tree.set(root); tree.prototype.event = this.open;

    //Start at the header section for PE, or at DOS header for ms-dos.
    
    tree.prototype.treeClick( (!msDos ? Tree.getNode(0).getNode(0) : Tree.getNode(0).getNode(0).getNode(0).getNode(0)).parentElement );
  },

  /*-------------------------------------------------------------------------------------------------------------------------
  Scan DLL import table.
  -------------------------------------------------------------------------------------------------------------------------*/

  fnPos: [], fnName: [], readDLL: function(vPos, len)
  {
    if(len) //Initialize data. Note the len is useless as it only covers part of the import table data so we use the "lengthV" method to give us the full import segment size.
    {
      //DLL import table array.

      format.des[6] = new Descriptor([format.dArray = new arrayType("Array Element ",[
        new dataType("DLL Array Functions Location 1", Descriptor.LUInt32),
        new dataType("Time Date Stamp", Descriptor.LUInt32),
        new dataType("Forward Chain", Descriptor.LUInt32),
        new dataType("DLL Name Location", Descriptor.LUInt32),
        new dataType("DLL Array Functions Location 2", Descriptor.LUInt32)
      ])]); format.des[6].offset = vPos;

      //DLL Name.

      format.des[7] = new Descriptor([format.dllName]);

      //DLL function array.

      format.des[8] = new Descriptor([format.funcArray = new arrayType("Array Element ",[
        new dataType("Import Name Location, or Index", format.is64bit ? Descriptor.LUInt64 : Descriptor.LUInt32),
      ])]);

      //DLL method name.

      format.des[9] = new Descriptor([new dataType("Address list index", Descriptor.LUInt16),format.funcName]);

      //Detailed information of each descriptor.

      format.des[6].setEvent(format, "dArrayInfo");

      //Data is in virtual address space.

      format.des[6].virtual = format.des[7].virtual = format.des[8].virtual = format.des[9].virtual = true;

      //Begin reading dll array. Note we use the remaining length of the virtual address as the dll import len only covers the dll array size.

      file.onRead(format, "readDLL", vPos); file.seekV(vPos); file.read(file.lengthV()); return;
    }

    //Create root node.

    var n = new treeNode("DLL Import Table",[24],true);

    //Scan The DLL Array.

    var pos1 = 0, pos2 = 0, fn1 = -1, fn2 = -1, nLoc = -1, fnEl = 0, fnElSize = !format.is64bit ? 4 : 8, str = "", z = -1, i = 0, dll = null, fnL1 = null, fnL2 = null; while((fn1|fn2) != 0)
    {
      fn1 = (file.tempD[pos1]|file.tempD[pos1+1]<<8|file.tempD[pos1+2]<<16|file.tempD[pos1+3]<<24);
      nLoc = (file.tempD[pos1+12]|file.tempD[pos1+13]<<8|file.tempD[pos1+14]<<16|file.tempD[pos1+15]<<24);
      fn2 = (file.tempD[pos1+16]|file.tempD[pos1+17]<<8|file.tempD[pos1+18]<<16|file.tempD[pos1+19]<<24);

      if(nLoc != 0)
      {
        //Read DLL name.

        str = ""; z = -1; i = (nLoc + format.baseAddress) - vPos; while(z != 0) { str += String.fromCharCode(z = file.tempD[i++]); }

        dll = new treeNode(str.substring(0,str.length-1),[28,nLoc + format.baseAddress, str.length]); n.add(dll);

        //Add function list nodes.

        fn1 += format.baseAddress; fn2 += format.baseAddress; fnL1 = new treeNode("Function array 1.h"); fnL2 = new treeNode("Function array 2.h"); dll.add(fnL1); dll.add(fnL2);

        //Read function list1.

        pos2 = fn1 - vPos; fnEl = 0; while(nLoc != 0)
        {
          if(!format.is64bit) { nLoc=file.tempD[pos2]|(file.tempD[pos2+1]<<8)|(file.tempD[pos2+2]<<16)|(file.tempD[pos2+3]<<24); }
          else { nLoc=(file.tempD[pos2]|(file.tempD[pos2+1]<<8)|(file.tempD[pos2+2]<<16))+(file.tempD[pos2+3]*format.s24)+(file.tempD[pos+4]*format.s32)+(file.tempD[pos2+5]*format.s40)+(file.tempD[pos2+6]*format.s48)+(file.tempD[pos2+7]*format.s56); }

          //Get function name

          if(nLoc != 0 && nLoc > 0)
          {
            nLoc += format.baseAddress; str = ""; z = -1; i = (nLoc - vPos) + 2; while(z != 0) { str += String.fromCharCode(z = file.tempD[i++]); }

            dll.add(str+"().dll",[36,nLoc, str.length]);
            
            //Function list 2 is used by the machine code section to call a an linked location from an export list.
            
            format.fnPos.push(fnEl + fn2); fnEl += fnElSize; format.fnPos.push(fnEl + fn2); format.fnName.push(str);
          }

          pos2 += fnElSize;
        }

        //Set function list size to function list nodes.

        fnEl += fnElSize; fnEl = !format.is64bit ? fnEl >> 2 : fnEl >> 3; fnL1.setArgs([32,fn1,fnEl]); fnL2.setArgs([32,fn2,fnEl]);
      }

      pos1+=20;
    }

    format.dArray.length(pos1>>4|pos1>>2); //Fast bitwise divide by 20.

    format.scanNode = false; file.tempD = []; format.node.setNode(n); if(!format.fnScan) { dModel.setDescriptor(format.des[6]); } else { format.disEXE(); } format.fnScan = true;
  },

  /*-------------------------------------------------------------------------------------------------------------------------
  Read the resource files in the EXE, or DLL.
  -------------------------------------------------------------------------------------------------------------------------*/

  rBase: 0, rDir: false, rTemp:[], readRes: function(vPos, len)
  {
    dModel.clear(); if(format.rBase == 0) //Initialize the data model only when user wants to read the resource files.
    {
      format.node.setArgs([0,0,17,vPos,len]); format.rBase = vPos; vPos = -2147483648; format.des[10] = new Descriptor([
        new dataType("Characteristics", Descriptor.LUInt32),
        new dataType("Date time stamp", Descriptor.LUInt32),
        new dataType("Major Version", Descriptor.LUInt16),
        new dataType("Minor Version", Descriptor.LUInt16),
        new dataType("Number Of Named Entries", Descriptor.LUInt16),
        new dataType("Number Of Id Entries", Descriptor.LUInt16),
        format.rArray = new arrayType("Dir",[
          new dataType("Name, or ID", Descriptor.LInt32),
          new dataType("Directory, or File", Descriptor.LInt32)
        ])
      ]); format.des[11] = new Descriptor([
        new dataType("File location", Descriptor.LUInt32),
        new dataType("File size", Descriptor.LUInt32),
        new dataType("Code Page", Descriptor.LUInt32),
        new dataType("Reserved", Descriptor.LUInt32)
      ]); format.des[12] = new Descriptor([
        new dataType("Name length", Descriptor.LUInt16),
        format.rLen=new dataType("Entire Name", Descriptor.LString16)
      ]);
      format.des[10].virtual = format.des[11].virtual = format.des[12].virtual = true; format.des[10].setEvent(format, "rDInfo"); format.des[11].setEvent(format, "rFInfo"); format.des[12].setEvent(format, "rNInfo");
    }
    format.rDir = vPos < 0; if(format.rDir) { vPos+=2147483648; } vPos += format.rBase; file.onRead(format, "dirData", vPos); file.seekV(vPos); file.readV(16);
  }, dirData: function(vPos) { file.onRead(format, "scanRes", vPos); if(format.rDir) { file.seekV(vPos+16); file.readV(((file.tempD[12]|(file.tempD[13]<<8))+(file.tempD[14]|(file.tempD[15]<<8)))<<3); }
  else { file.seekV(vPos); file.readV(16); } }, scanRes: function(vPos)
  {
    //Load in the directory array.

    format.rTemp.loc = vPos; if(format.rDir)
    {
      for(var i = 0, e = file.tempD.length - 1; i < e; i+=8)
      {
        format.rTemp.push(new Number(file.tempD[i]|(file.tempD[i+1]<<8)|(file.tempD[i+2]<<16)|(file.tempD[i+3]<<24)));
        format.rTemp.push(file.tempD[i+4]|(file.tempD[i+5]<<8)|(file.tempD[i+6]<<16)|(file.tempD[i+7]<<24));
      }
      format.rScanDir(0);
    }

    //Else it is a location to a file with a size parameter.

    else { var a1 = format.node.getArgs(); a1.splice(0,2); var n = new treeNode(format.node.innerHTML,a1,true); n.add("File info.h",[44,vPos]); n.add("File data",[1,format.baseAddress+(file.tempD[0]|(file.tempD[1]<<8)|(file.tempD[2]<<16)|(file.tempD[3]<<24)),(file.tempD[4]|(file.tempD[5]<<8)|(file.tempD[6]<<16)|(file.tempD[7]<<24)),true]); format.scanNode = false; format.node.setNode(n); format.open(a1); return;  }
  },
  rScanDir: function(i,name)
  {
    //Load in any dir/file names.

    if(name != undefined){ format.rTemp[i].name = name; i+=2; } for(;i<format.rTemp.length;i+=2) { if(format.rTemp[i] < 0){ file.onRead(format, "rGetNameLen", i); file.seekV((format.rTemp[i] + 2147483648)+format.rBase); file.readV(2); return; } else { format.rTemp[i].name = format.rTemp[i] + ""; } }
    
    //Create directory nodes.
    
    var a1 = format.node.getArgs(), a2 = null; a1.splice(0,2); var n = new treeNode(format.node.innerHTML,a1,true); n.add("Directory info.h",[40,format.rTemp.loc]);
    
    for(var i = 0, e = format.rTemp.length, t = null; i < e; i+=2)
    {
      a2 = [-3,format.rTemp[i+1]]; if(format.rTemp[i] > 0) { a2.push(1); } else { a2.push(48);a2.push(format.rTemp[i]+2147483648+format.rBase); }
      
      t = new treeNode("" + format.rTemp[i].name,a2); t.add(""); n.add(t,1);
    }

    format.scanNode = false; format.node.setNode(n); format.open(a1); format.rTemp = [];
  },
  rGetNameLen: function(i) { file.onRead(format, "rGetName", i); file.seekV((format.rTemp[i] + 2147483650)+format.rBase); file.readV((file.tempD[0]<<1)|(file.tempD[1]<<9)); }, rGetName: function(i) { for(var o = "", t = 0;t<(file.tempD.length-1);o+=String.fromCharCode((file.tempD[t]|(file.tempD[t+1]<<8))),t+=2); format.rScanDir(i,o); },

  /*-------------------------------------------------------------------------------------------------------------------------
  Read the exportable methods and data lists. Allow disassembly of callable methods and driver functions in the windows system.
  -------------------------------------------------------------------------------------------------------------------------*/

  readExport: function(vPos,len)
  {
    if(len) //Initialize data.
    {
      format.des[13] = new Descriptor([
        new dataType("Characteristics", Descriptor.LUInt32),
        new dataType("Time Date Stamp", Descriptor.LUInt32),
        new dataType("Major Version", Descriptor.LUInt16),
        new dataType("Minor Version", Descriptor.LUIn16),
        new dataType("Export Name location", Descriptor.LUInt32),
        new dataType("Base", Descriptor.LUInt32),
        new dataType("Number Of Functions", Descriptor.LUInt32),
        new dataType("Number Of Names, and ordinals", Descriptor.LUInt32),
        new dataType("Address list location", Descriptor.LUInt32),
        new dataType("Method list location", Descriptor.LUInt32),
        new dataType("Method order location", Descriptor.LUInt32)
      ]);
      format.des[14] = new Descriptor([format.eAList = new arrayType("Address List",[new dataType("Address index list", Descriptor.LInt32)])]);
      format.des[15] = new Descriptor([format.eNList = new arrayType("Name List",[new dataType("Name location", Descriptor.LInt32)])]);
      format.des[16] = new Descriptor([format.eOList = new arrayType("Ordinal List",[new dataType("Name Address Index", Descriptor.LInt16)])]);
      format.des[17] = new Descriptor([format.eStr = new dataType("Export name", Descriptor.String8)]);
      format.des[18] = new Descriptor([format.eStrName = new dataType("Name", Descriptor.String8)]);
      format.des[13].virtual = format.des[14].virtual = format.des[15].virtual = format.des[16].virtual = format.des[17].virtual = format.des[18].virtual = true;
      format.des[13].setEvent(format, "eInfo"); format.des[14].setEvent(format, "eInfo"); format.des[15].setEvent(format, "eInfo");
      format.des[16].setEvent(format, "eInfo");format.des[17].setEvent(format, "eInfo"); format.des[18].setEvent(format, "eInfo");
      format.des[13].offset = vPos; file.onRead(format,"readExport",vPos);file.seekV(vPos);file.read(len); return;
    }

    //Parse binary data.

    format.des[17].offset = (file.tempD[12]|file.tempD[13]<<8|file.tempD[14]<<16|file.tempD[15]<<24) + format.baseAddress; //Export file name location.
    var eBase = (file.tempD[16]|file.tempD[17]<<8|file.tempD[18]<<16|file.tempD[19]<<24) - 1;
    var eFn = file.tempD[20]|file.tempD[21]<<8|file.tempD[22]<<16|file.tempD[23]<<24;
    var eSize = file.tempD[24]|file.tempD[25]<<8|file.tempD[26]<<16|file.tempD[27]<<24;
    format.des[14].offset = (file.tempD[28]|file.tempD[29]<<8|file.tempD[30]<<16|file.tempD[31]<<24) + format.baseAddress; //Address list.
    format.des[15].offset = (file.tempD[32]|file.tempD[33]<<8|file.tempD[34]<<16|file.tempD[35]<<24) + format.baseAddress; //Name list.
    format.des[16].offset = (file.tempD[36]|file.tempD[37]<<8|file.tempD[38]<<16|file.tempD[39]<<24) + format.baseAddress; //Ordinal list.
    format.eAList.length(eFn);format.eNList.length(eSize);format.eOList.length(eSize);

    //Create export node.

    var a = format.node.getArgs(); a[0] = 13; var n = new treeNode(format.node.innerHTML,a,true); n.add("Export info.h",52);

    //Get the export name.

    var str = "", z = -1, i = format.des[17].offset - vPos, e = 0; while(z != 0) { str += String.fromCharCode(z = file.tempD[i++]); }

    //Add export lists to the export name node.

    format.eStr.length(str.length); str=str.substring(0,str.length-1); var t1 = new treeNode(str,68), t2 = null; n.add(t1); t1.add("Address list location.h",56); t1.add("Name list location.h",60); t1.add("Order list location.h",64);

    //Entires that are named are set true in mList so that we can skip them when adding the uname entires.

    var mList = []; for(i = 0;i < eFn;mList[i++] = false);

    //Add all named export entireties.

    var aList = format.des[14].offset - vPos, ordinal = 0, i1 = format.des[15].offset - vPos, i2 = format.des[16].offset - vPos; for(e = i1 + (eSize << 2);i1 < e;i1+=4,i2+=2)
    {
      //Get ordinal and set the address as mapped.

      mList[ordinal = (file.tempD[i2]|file.tempD[i2+1]<<8)+eBase] = true;

      //Get method name.

      str = ""; z = -1; i = file.tempD[i1]|file.tempD[i1+1]<<8|file.tempD[i1+2]<<16|file.tempD[i1+3]<<24; i = (i + format.baseAddress) - vPos; while(z != 0) { str += String.fromCharCode(z = file.tempD[i++]); }

      //Parse export name data into node.

      t2 = new treeNode(str+"() #"+ordinal,[72,(i-str.length)+vPos,str.length]);

      //Get the address location of ordinal in address list.
      
      ordinal = aList + (ordinal << 2); ordinal = (file.tempD[ordinal]|file.tempD[ordinal+1]<<8|file.tempD[ordinal+2]<<16|file.tempD[ordinal+3]<<24) + format.baseAddress;

      //Add goto location and disassembly under export method or data.
      
      t2.add("Goto Location.h",[1,ordinal,1,true]); t2.add("Disassemble Location.h",[3,ordinal]); t1.add(t2);
    }

    //Add the unnamed entries.

    i1 = aList; for(i = 0;i < mList.length;i++,i1+=4)
    {
      if(!mList[i])
      {
        ordinal = (file.tempD[i1]|file.tempD[i1+1]<<8|file.tempD[i1+2]<<16|file.tempD[i1+3]<<24) + format.baseAddress;
        t2 = new treeNode("No_Name() #"+i,1); t2.add("Goto Location.h",[1,ordinal,true]); t2.add("Disassemble Location.h",[3,ordinal]); t1.add(t2);
      }
    }

    //Set the parsed data to node.
    
    format.scanNode = false; file.tempD = []; format.node.setNode(n); format.open(a);
  },

  /*-------------------------------------------------------------------------------------------------------------------------
  Relocations do not need to be read or applied because everything is mapped to the proper address alignments.
  -------------------------------------------------------------------------------------------------------------------------*/

  readRelocation: function(vPos,size)
  {
    format.scanNode =  false; dModel.clear(); file.seekV(vPos); ds.setType(15, 0, size, true);
    
    info.innerHTML = "<html>Relocations are used if the program is not loaded at it's preferred base Address set in the op header.<br /><br />" +
    "The difference is added to locations defined in the address list in this relocation section.<br /><br />" +
    "Relocations are not needed, for this disassembler as the program is always mapped at it's preferred base address.<br /><br />" +
    "A reader can be designed for the relocation section, but is not really necessary.<br /><br /><br />" +
    "Relocations are common in 16Bit, or 32Bit x86. However, 64bit x86 machine code uses relative addresses.<br /><br />" +
    "Relative addresses are added to the current instruction position in the binary.<br /><br />" +
    "Allowing the binary to be placed anywhere in memory without having to change the address locations.<br /><br />" +
    "It is very rare for there to be relocations, if it is a 64bit x86 binary.</html>";
  },

  /*-------------------------------------------------------------------------------------------------------------------------
  Section readers that are not yet implemented.
  -------------------------------------------------------------------------------------------------------------------------*/

  noReader: function(vPos, size)
  {
    format.scanNode =  false; dModel.clear(); file.seekV(vPos); ds.setType(15, 0, size, true);
    
    info.innerHTML = "No reader, for this section.";
  },

  /*-------------------------------------------------------------------------------------------------------------------------
  Read a zero terminated string and call back function.
  -------------------------------------------------------------------------------------------------------------------------*/

  callBack: function(){}, stringZ: function(str)
  {
    for(var i=0,str=str||"";i<file.tempD.length;i++)
    {
      if(file.tempD[i]==0){format.callBack(str);return;}

      str+=String.fromCharCode(file.tempD[i]);
    }

    //Read additional 32 bytes if the end of the string has not been reached.

    file.onRead(format,"stringZ");file.seekV(file.tempD.length+file.tempD.offset);file.readV(32);
  },

  /*-------------------------------------------------------------------------------------------------------------------------
  Tree event handling.
  -------------------------------------------------------------------------------------------------------------------------*/

  open: function(n)
  {
    //If there is a node being scanned it is important that we do not accept any new commands.

    if(format.scanNode){ alert("The node \""+format.node.innerHTML+"\" is still being read and parsed.\r\nAccepting new commands can corrupt the data buffer."); return; }

    //No nodes are being read or parsed we then can accept the command.

    var e = n.getArgs ? (format.node = n).getArgs() : n, cmd = parseInt(e[0]);

    //Check if negative value which are used to load in sections.

    if(cmd < 0) { format.scanNode = true; format.readSec[-(cmd+1)](parseFloat(e[1]),parseInt(e[2])); return; }

    //Check if the argument is a command such as start disassembling code, or select bytes.

    des = cmd>>2; cmd &= 3; if(cmd >= 1)
    {
      //CMD 1 is select bytes, or message only.

      if(cmd == 1)
      {
        dModel.clear(); if(e.length > 2)
        {
          if(e[3] == "false") { file.seek(parseInt(e[1])); ds.setType(15, 0, parseInt(e[2]), false); }
          else { file.seekV(parseInt(e[1])); ds.setType(15, 0, parseInt(e[2]), true); }
        }
        info.innerHTML = format.msg[des];
      }

      //Begin disassembling ms-dos app. MS dos files are by default 16 bit x86.

      else if(cmd == 2) { format.disV = parseInt(e[1]); coreReady = format.disMSDos; loadCore("core/x86/dis-x86.js"); }

      //Begin disassembling microsoft app.

      else if(cmd == 3)
      {
        format.disV = parseFloat(e[1]); coreReady = format.disEXE;
        
        if(format.coreType == 0x014C || format.coreType == 0x8664) { loadCore("core/x86/dis-x86.js"); } else
        {
          info.innerHTML = "Core type instruction set not yet supported.";
        }
      }
    }

    //Else it is a data model node.

    else
    {
      if(e.length > 1){ format.des[des].offset = parseInt(e[1]); }
      
      //In special cases the length of a data can be included.

      if(e.length > 2)
      {
        //Strings that have no encoded length and are zero byte terminated,

        if(des == 7){ format.dllName.length(parseInt(e[2])); }
        if(des == 8){ format.funcArray.length(parseInt(e[2])); }
        if(des == 9){ format.funcName.length(parseInt(e[2])); }
        if(des == 18){ format.eStrName.length(parseInt(e[2])); }
      }
      
      dModel.setDescriptor(format.des[des]);
    }
  },

  /*-------------------------------------------------------------------------------------------------------------------------
  Detailed information output goes bellow this comment.
  -------------------------------------------------------------------------------------------------------------------------*/

  //Message output for byte selection command.

  msg: [
    //No information yet for sections, or data in development.
    "No information for this data or section yet.",
    //DOS header.
    "<html>This is the original DOS header. Which must be at the start of all windows binary files.<br /><br />Today the reserved bytes are used to locate to the new Portable executable header format.<br /><br />" +
    "However, on DOS this header still loads as the reserved bytes that locate to the PE header do nothing in DOS.<br /><br />Thus the small 16 bit binary at the end will run. " +
    "Which normally contains a small 16 bit code that prints the message that this program can not be run in DOS mode.<br /><br />Though it can be a full-fledged DOS version of the program.</html>",
    //Microsoft headers.
    "<html>The headers setup the Microsoft binary virtual space.<br /><br />Otherwise The import table can not be located.<br /><br />" +
    "Export Table can not be located.<br /><br />" +
    "Files that are included in the binary. Called Resource Files. Also can not be located.<br /><br />" +
    "Nether can the machine code Start position be located.</html>",
    //Export
    "<html>Once the headers are read, then the program is setup in virtual space.<br /><br />" +
    "The Export section is a list of names that locate to a machine code in RAM.<br /><br />" +
    "Methods can be imported by name, or by number they are in the export Address list.<br /><br />" +
    "A import table specifies which files to load to memory. If not already loaded.<br /><br />" +
    "The method list in the import table is replaced with the export locations in RAM from the other file.<br /><br />" +
    "This allows the other binary to directly run methods by using the import location as a relative address.</html>",
    //Resource.
    "<html>Files that can be read within the application, or DLL. Such as pictures, images, audio files.<br /><br />The first Icon that is read is the programs ICon image.<br /><br />" +
    "Each address location is added to the start of the resource section.</html>"
  ],

  //MZ header information.

  mzHeader: function(i)
  {
    if( i < 0 ) { this.sig.length(2); this.r1.length(8); this.r2.length(20); }

    info.innerHTML = format.msg[0];
  },

  //MS-dos relocations information.

  mzRel: function(i)
  {
    if( i < 0 ) { this.sig.length(2); this.r1.length(8); this.r2.length(20); }
  
    info.innerHTML = format.msg[0];
  },

  //PE header information.

  peHeader: function(i)
  {
    if( i < 0 ) { this.sig.length(4); }
  
    info.innerHTML = format.msg[0];
  },

  //OP header information.

  opHeader: function(i)
  {
    if( i < 0 ) { this.sig.length(2); }
  
    info.innerHTML = format.msg[0];
  },

  //Data directory array information.

  dirArray: function(i)
  {
    if( i < 0 ) { }
  
    info.innerHTML = format.msg[0];
  },

  //Section array information.

  secArray: function(i)
  {
    if( i < 0 ) { this.r1.length(12); }
  
    info.innerHTML = format.msg[0];
  },

  //DLL import array info.

  dArrayInfo: function(i)
  {
    if( i < 0 )
    {
      info.innerHTML = "<html>Methods that are imported from other files using the export table section.<br /><br />" +
      "Each import file is loaded to RAM memory. Each import has two method lists.<br /><br />" +
      "The first list is wrote over in RAM with the location to each export method location.<br /><br />" +
      "This allows the binary to directly run methods without rewriting, or changing machine code.<br /><br />" +
      "It is easy to map when a method call is done in machine code.</html>"; return;
    }

    info.innerHTML = format.msg[0];
  },
  
  //Resource directory information.

  rDInfo: function(i, pos)
  {
    if( i < 0 ) { format.rArray.length((file.data[pos+12]|(file.data[pos+13]<<8))+(file.data[pos+14]|(file.data[pos+15]<<8))); }
    
    info.innerHTML = format.msg[0];
  },

  //Resource directory file information.

  rFInfo: function(i)
  {
    info.innerHTML = format.msg[0];
  },
    
  //Resource entire name.

  rNInfo: function(i, pos)
  {
    if( i < 0 ) { format.rLen.length((file.data[pos]<<1)|(file.data[pos+1]<<9)); }
    
    info.innerHTML = format.msg[0];
  },

  //Grouping together the export information for now.

  eInfo: function(i, pos)
  {
    info.innerHTML = format.msg[0];
  },

  //Used to identify bad file signatures in the case of a corrupted application.

  badSig: function(i)
  { 
    info.innerHTML = "A bad signature has been encountered, so the application is corrupted!";
  },

  /*-------------------------------------------------------------------------------------------------------------------------
  Disassembly methods goes bellow this comment. Note it is possible to add am scanner that translates code to C/C++.
  -------------------------------------------------------------------------------------------------------------------------*/

  //The x86 core is ready and we can now begin ms dos disassembly.

  disMSDos: function()
  {
    core.showInstructionHex = false;

    core.scan = format.dosScan; core.addressMap = true; core.resetMap(); core.bitMode = 0;
    
    core.setCodeSeg((Math.random()*0x2000)<<3); dModel.setCore(core); dModel.coreDisLoc(format.disV,true);
  },

  //The x86 core is ready and we can now begin Microsoft application disassembly.

  disEXE: function()
  {
    //Only begin disassembly if the import table is read and function calls are mapped.

    if(!format.fnScan){format.fnScan=true;for(var e=Tree.getNode(0),s=null,i=0;i<e.length();i++){if((s=e.getNode(i)).getArgs()[0]==-2){format.open(s);return;}}}

    core.showInstructionHex = false;

    core.scanReset(); core.addressMap = true; core.resetMap(); core.bitMode = format.is64bit ? 2 : 1;

    //Set function call address list and data to core.

    core.set(format.fnPos,format.fnName); dModel.setCore(core); dModel.coreDisLoc(format.disV,true);
  },

  //MSDos code scanner. Ensures proper disassembly of old 16 ms dos applications.

  Dos_exit: 0, dosScan: function(crawl)
  {
    var i = core.instruction + " " + core.insOperands;
    
    if( format.Dos_exit == 0 && ( i.startsWith("MOV AX,4C") || i.startsWith("MOV AH,4C") ) ) { format.Dos_exit = 1; }
    else if( format.Dos_exit == 1 && ( i.indexOf("AX,") > 0 || i.indexOf("AH,") > 0 ) ) { format.Dos_exit = 0; }
    if( format.Dos_exit == 1 && i == "INT 21" ) { format.Dos_exit = 2; }
    
    return( format.Dos_exit == 2 || i.startsWith("RET") || i.startsWith("JMP") || i == "INT 20" );
  }
}

//The data descriptor calls this function when we go to click on an address we wish to disassemble.

dModel.coreDisLoc = function(virtual,crawl)
{
  //Begin data check.

  format.Dos_exit = 0; this.cr = crawl; core.setAddress(virtual);

  //If the address we wish to disassemble is within the current memory buffer then we do not have to read any data.

  file.bufRead(this, "dis"); file.seekV(format.disV = virtual); file.initBufV();
}

dModel.dis = function()
{
  //Set binary code relative position within the buffer.

  core.setBinCode(file.dataV,format.disV - file.dataV.offset);
  
  //Begin disassembling the code.
  
  info.innerHTML = "<pre>" + core.disassemble(this.cr) + "</pre>";

  window.offset.slen = 1; window.virtual.slen = core.getAddress() - format.disV;
    
  dModel.adjSize(); dModel.update(); file.seekV(format.disV);
}