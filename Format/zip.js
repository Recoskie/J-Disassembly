//Everything in the format reader must be defined as an object called format.
//This ensures that all data in the format reader is overwritten when loading in a new format.

format = {
  sig: new dataType("Signature", Descriptor.Other), fName: new dataType("File name", Descriptor.String8),
  dFelid: new dataType("Data Felid", Descriptor.Other), comment: new dataType("Comment", Descriptor.String8),
  des: [],
  
  /*As we read each PK file entry we split the full file path apart in forward slash.
  We add nodes to root for the full file path and store the current node and it's file path.
  The value cRoot is the current path node. The value path is the current path we are at.
  As we add more file paths from each PK header we check which folder node changed in the path from the current path.
  We move up one node to match the point of change. Then add non existing tree nodes.
  Since file paths are grouped together in order in a zip this is the fastest way to build the file structure of the zip.*/
  
  root: undefined, cRoot: undefined, path: [],
  
  //Begins setting up the zip analysis algorithm.
  
  load: function()
  {
    //Setup descriptors.

    this.des[0] = new Descriptor([
      this.sig,
      new dataType("Min Version", Descriptor.LUInt16),
      new dataType("Flag", Descriptor.LUInt16),
      new dataType("Compression method", Descriptor.LUInt16),
      new dataType("Last Modified (Time)", Descriptor.LUInt16),
      new dataType("Last Modified (Date)", Descriptor.LUInt16),
      new dataType("CRC-32", Descriptor.LUInt32),
      new dataType("Compressed Size", Descriptor.LUInt32),
      new dataType("Uncompressed Size", Descriptor.LUInt32),
      new dataType("File name Length", Descriptor.LUInt16),
      new dataType("Data felid len", Descriptor.LUInt16),
      this.fName, this.dFelid
    ]);
    this.des[1] = new Descriptor([
      this.sig,
      new dataType("CRC-32", Descriptor.LUInt32),
      new dataType("Compressed Size", Descriptor.LUInt32),
      new dataType("Uncompressed Size", Descriptor.LUInt32)
    ]);
    this.des[2] = new Descriptor([
      this.sig,
      new dataType("Version used", Descriptor.LUInt16),
      new dataType("Min Version", Descriptor.LUInt16),
      new dataType("Flag", Descriptor.LUInt16),
      new dataType("Compression method", Descriptor.LUInt16),
      new dataType("Last Modified (Time)", Descriptor.LUInt16),
      new dataType("Last Modified (Date)", Descriptor.LUInt16),
      new dataType("CRC-32", Descriptor.LUInt32),
      new dataType("Compressed Size", Descriptor.LUInt32),
      new dataType("Uncompressed Size", Descriptor.LUInt32),
      new dataType("File name Length", Descriptor.LUInt16),
      new dataType("Data felid len", Descriptor.LUInt16),
      new dataType("Comment len", Descriptor.LUInt16),
      new dataType("Disk Number", Descriptor.LUInt16),
      new dataType("Internal attributes", Descriptor.LUInt16),
      new dataType("External attributes", Descriptor.LUInt32),
      new dataType("Offset", Descriptor.LUInt32),
      this.fName, this.dFelid, this.comment
    ]);
    this.des[3] = new Descriptor([
      this.sig,
      new dataType("Disk Number", Descriptor.LUInt16),
      new dataType("Disks", Descriptor.LUInt16),
      new dataType("Directory", Descriptor.LUInt16),
      new dataType("Directories", Descriptor.LUInt16),
      new dataType("Directory size", Descriptor.LUInt32),
      new dataType("Directory offset", Descriptor.LUInt32),
      new dataType("Comment size", Descriptor.LUInt16),
      this.comment
    ]);
    this.des[4] = new Descriptor([
      this.sig,
      new dataType("End 64 Size", Descriptor.LUInt64), //Note -44 bytes.
      new dataType("Version", Descriptor.LUInt16),
      new dataType("Min Version", Descriptor.LUInt16),
      new dataType("Disk Number", Descriptor.LUInt32),
      new dataType("Disks", Descriptor.LUInt32),
      new dataType("Directory", Descriptor.LUInt64),
      new dataType("Directories", Descriptor.LUInt64),
      new dataType("Directory size", Descriptor.LUInt64),
      new dataType("Directory offset", Descriptor.LUInt64),
      this.dFelid
    ]);
    this.des[5] = new Descriptor([
      this.sig,
      new dataType("Disks 64", Descriptor.LUInt32),
      new dataType("Dir End64 Offset", Descriptor.LUInt64),
      new dataType("Disks", Descriptor.LUInt32)
    ]);
    this.sig.length(4);

    //Setup header event handlers.

    this.des[0].setEvent(this, "zipInfo"); this.des[1].setEvent(this, "dataInfo");
    this.des[2].setEvent(this, "dirInfo"); this.des[3].setEvent(this, "endInfo");
    this.des[4].setEvent(this, "end64Info"); this.des[5].setEvent(this, "loc64Info");

    //Combine information that is the same between attributes.

    this.zipInfoData[13] = this.zipInfoData[13] + this.multiPartZip;
    this.loc64InfoData[1] = this.loc64InfoData[1] + this.multiPartZip;
    this.loc64InfoData[3] = this.loc64InfoData[3] + this.multiPartZip;
    this.endInfoData[2] = this.zipInfoData[1]; this.endInfoData[2] = this.zipInfoData[2];
    this.endInfoData[3] = this.endInfoData[3] + this.multiPartZip;
    this.endInfoData[4] = this.endInfoData[4] + this.multiPartZip;
    this.endInfoData[5] = this.endInfoData[5] + this.multiPartZip;
    this.endInfoData[6] = this.endInfoData[6] + this.multiPartZip;
    
    //Setup root node.
    
    this.root = new treeNode(file.name.substring(file.name.lastIndexOf("/")+1,file.name.length),[],true);

    this.cRoot = this.root; //The current path node.

    //Begin scanning the zip.

    file.onRead(this, "scan"); file.seek(this.fpos); file.read(4096);
  },

  //Scan the zip.

  bpos: 0, fpos: 0, fdata: 0, scan: function()
  {
    var sig, size = 0, strLen = 0, extData = 0, end = 0, name = "";

    while( this.bpos < 4092 )
    {
      sig = (file.tempD[this.bpos + 3] << 24) | (file.tempD[this.bpos + 2] << 16) | (file.tempD[this.bpos + 1] << 8) | file.tempD[this.bpos];
      
      if( sig == 0x04034B50 )
      {
        //If buffer pos is grater than 4062 then there is not enough data to read the file header properly.

        if( this.bpos >= 4062 ){ file.onRead(this, "scan"); file.seek(this.fpos); this.bpos = 0; file.read(4096); return; }

        //The file path is needed to generate the tree structure of the zip. The extra data is needed in case of extended size if existent for zip64.

        strLen = (file.tempD[this.bpos + 27] << 8) | file.tempD[this.bpos + 26]; extData = (file.tempD[this.bpos + 29] << 8) | file.tempD[this.bpos + 28];

        //If there is not enough data to read the variable length fields at the end of the file header then we must start over with more data.

        if( this.bpos >= (4062-(strLen+extData)) ){ file.onRead(this, "scan"); file.seek(this.fpos); this.bpos = 0; file.read(4096); return; }

        //Read the compressed file size.

        size = (file.tempD[this.bpos + 21] << 24) | (file.tempD[this.bpos + 20] << 16) | (file.tempD[this.bpos + 19] << 8) | file.tempD[this.bpos + 18];

        //Size should never be a negative singed value. If this happens it is a ZIP64 signature.
        
        if( size == 0xFFFFFFFF ){ size = 0; } this.bpos += 30;

        //The file path name.

        end = this.bpos + strLen; while( this.bpos < end ){ name += String.fromCharCode(file.tempD[this.bpos++]) }

        //Check for zip64 compressed file size.

        end = this.bpos + extData; while( this.bpos < end )
        {
          if( file.tempD[this.bpos] == 1 && file.tempD[this.bpos + 1] == 0 && ((file.tempD[this.bpos + 3] << 8) | file.tempD[this.bpos + 2]) >= 16 )
          {
            size = (file.tempD[this.bpos + 19] * (2**56)) + (file.tempD[this.bpos + 18] * (2**48)) + (file.tempD[this.bpos + 17] * (2**40)) + (file.tempD[this.bpos + 16] * (2**32)) +
            (file.tempD[this.bpos + 15] * (2**24)) + ((file.tempD[this.bpos + 14] << 16) | (file.tempD[this.bpos + 13] << 8) | file.tempD[this.bpos + 12]); this.bpos = end;
          }
          else { this.bpos += ((file.tempD[this.bpos + 3] << 8) | file.tempD[this.bpos + 2]) + 4; }
        }

        //Add the dir, and add the data node if size is > 0, and skip the files data to quickly read the next file signature.
        
        this.bpos = end; this.addDir(name, this.fpos); this.bpos += size; this.fpos += 30 + strLen + extData + size; name = "";
      }
      
      //If a file signature had zero size then the preceding data till a data descriptor signature identifies the files data end.
      //The data descriptor signature has a number that should match how many bytes we read before we reached the data descriptor signature (end of the files data).
      //If the number does not match then the file is corrupted.

      else
      {
        this.bpos += 1; this.fpos += 1;
      }
    }
    
    if( this.fpos < file.size ) { file.onRead(this, "scan"); this.bpos = 0; file.seek(this.fpos); file.read(4096); } else { this.bpos = this.fpos = this.fdata = 0; this.done(); }
  },

  //Algorithm for adding tree nodes. It is optimized based on how zip organizes paths.

  addDir: function(path, pos)
  {
    var path = path.split("/"), level = this.path.length, change = 0, exists = false; if(path[path.length-1] == ""){ path.pop(); }

    //Find which part of the path dose not match the current path.

    for( var e = this.path.length < path.length ? this.path.length : path.length; change < e; change++ )
    {
      if( path[change] != this.path[change] ){ break; }
    }

    //Move up from the current path to where the path change occurred.

    while( change < level ) { level--; this.cRoot = this.cRoot.parentNode; }

    //Move through the path at the point of change. 

    while( path.length > level )
    {
      //If node exists set it to the current Path node. It is possible that it was previously added from a different path.

      exists = false; for( var e = this.cRoot.length(), el = 0; el < e; el++ )
      {
        if( path[level] == this.cRoot.getNode(el).name ) { exists = true; this.cRoot = this.cRoot.getNode(el); break; }
      }

      //Create Node if it does not exist, then set it to the current path node.

      if(!exists) { this.cRoot.add(this.cRoot = new treeNode(path[level], [2, pos])); }

      //Move up one in path position.

      level++;
    }

    //The current path is now the path we just added.
    
    this.path = path;
  },

  //Done scanning the zip file.

  done: function()
  {
    //Set binary tree view, and enable IO system events.

    Tree.set(this.root); tree.prototype.event = this.open;

    //We no longer need the root node once set as html to the tree.

    this.root = this.cRoot = undefined; this.path = [];
      
    //basic zip info.

    dModel.clear();
  
    info.innerHTML = "<html>The zip file format is used as a container for mobile (android, iPhone) applications, and java applications, and also Microsoft office documents as well as being useful for users to store files as a compressed zip file.<br /><br />" +
      "Java uses the zip format to store application files as a single file as a runnable file called an java jar.<br /><br />" +
      "Android APK applications are stored in zip files to save space, and to keep applications organized.<br /><br />" +
      "Apple iPhone IPA applications are stored in zip files to also save space and to keep applications organized.<br /><br />" +
      "Disassembling android and iPhone apps is supported by JDisassembly, but you will first need to decompress the application file as a zip, then find the application file in the IPA, or APK to open the application binary in JDisassembly.<br /><br />" +
      "Microsoft stores office document files into compressed zip files to save space and to keep pictures and models used in the office document organized as one file.</html>";
  },

  //Decode the extended data field information.

  /*public void extendedData()
  {
    file.Events = false;

    byte[] d = new byte[]{}; String out = "<html>Extra data field is a set of 2 byte pairs (code pair type) with a value that specifies the number of bytes to read.<br /><br />" +
    "The extra data field adds additional information about the file or entire, or extends values.<br /><br />";

    out += "<table border='1'><tr><td>Description</td><td>Hex</td><td>Value</td></tr>";

    //Get the data.

    try { file.seek( Offset.selectPos() ); d = new byte[ (int)(Offset.selectEnd() - file.getFilePointer()) + 1 ]; file.read(d); } catch( java.io.IOException er ) { }

    //Analyze the data.

    int pos = 0, end = d.length - 3; int CMD = 0; String Hex = ""; long val = 0; while( pos < end )
    {
      CMD = ( ( d[pos + 1] & 0xFF ) << 8 ) | ( d[pos] & 0xFF );
      Hex = String.format("%1$02X", d[pos] ) + " " + String.format("%1$02X", d[pos + 1] );

      //The unix time date stamp.

      if( CMD == 0x5455 )
      {
        out += "<tr><td>Unix Time Date stamps (0x" + String.format("%1$04X", CMD ) + ").</td><td>" + Hex + "</td><td>" + CMD + "</td></tr>";

        int size = ( ( d[pos + 3] & 0xFF ) << 8 ) | ( d[pos + 2] & 0xFF ); Hex = String.format("%1$02X", d[pos + 2] ) + " " + String.format("%1$02X", d[pos + 3] );

        out += "<tr><td>Time stamp len.</td><td>" + Hex + "</td><td>" + ( size > 28 ? "Error (" + size + " > 13)" : size ) + "</td></tr>"; size = size > 13 ? 0 : size; pos += 4;

        if( size > 0 )
        {
          val = d[pos] & 0xFF; Hex = String.format("%1$02X", d[pos] );

          out += "<tr><td>Flag settings.</td><td>" + Hex + "</td><td>" + val + "</td></tr>"; pos += 1; size -= 1;
        }

        if( size > 0 )
        {
          val = ( ( d[pos + 3] & 0xFF ) << 24 ) | ( ( d[pos + 2] & 0xFF ) << 16 ) | ( ( d[pos + 1] & 0xFF ) << 8 ) | ( d[pos] & 0xFF );
          Hex = String.format("%1$02X", d[pos] ) + " " + String.format("%1$02X", d[pos + 1] )+ " " + String.format("%1$02X", d[pos + 2] )+ " " + String.format("%1$02X", d[pos + 3] );

          out += "<tr><td>Last Modification.</td><td>" + Hex + "</td><td>" + val + "</td></tr>"; pos += 4; size -= 4;
        }

        if( size > 0 )
        {
          val = ( ( d[pos + 3] & 0xFF ) << 24 ) | ( ( d[pos + 2] & 0xFF ) << 16 ) | ( ( d[pos + 1] & 0xFF ) << 8 ) | ( d[pos] & 0xFF );
          Hex = String.format("%1$02X", d[pos] ) + " " + String.format("%1$02X", d[pos + 1] )+ " " + String.format("%1$02X", d[pos + 2] )+ " " + String.format("%1$02X", d[pos + 3] );

          out += "<tr><td>Last accessed.</td><td>" + Hex + "</td><td>" + val + "</td></tr>"; pos += 4; size -= 4;
        }

        if( size > 0 )
        {
          val = ( ( d[pos + 3] & 0xFF ) << 24 ) | ( ( d[pos + 2] & 0xFF ) << 16 ) | ( ( d[pos + 1] & 0xFF ) << 8 ) | ( d[pos] & 0xFF );
          Hex = String.format("%1$02X", d[pos] ) + " " + String.format("%1$02X", d[pos + 1] )+ " " + String.format("%1$02X", d[pos + 2] )+ " " + String.format("%1$02X", d[pos + 3] );

          out += "<tr><td>Creation time.</td><td>" + Hex + "</td><td>" + val + "</td></tr>"; pos += 4; size -= 4;
        }
      }

      //Compressed file attributes as 64 bit fields.

      else if( CMD == 0x0001 )
      {
        out += "<tr><td>zip64 (0x" + String.format("%1$04X", CMD ) + ").</td><td>" + Hex + "</td><td>" + CMD + "</td></tr>";

        int size = ( ( d[pos + 3] & 0xFF ) << 8 ) | ( d[pos + 2] & 0xFF );
        Hex = String.format("%1$02X", d[pos + 2] ) + " " + String.format("%1$02X", d[pos + 3] );

        out += "<tr><td>zip64 len.</td><td>" + Hex + "</td><td>" + ( size > 28 ? "Error (" + size + " > 28)" : size ) + "</td></tr>"; size = size > 28 ? 0 : size; pos += 4;

        if( size > 0 )
        {
          val = ( ( d[pos + 7] & 0xFF ) << 56 ) | ( ( d[pos + 6] & 0xFF ) << 48 ) | ( ( d[pos + 5] & 0xFF ) << 40 ) | ( ( d[pos + 4] & 0xFF ) << 32 ) |
          ( ( d[pos + 3] & 0xFF ) << 24 ) | ( ( d[pos + 2] & 0xFF ) << 16 ) | ( ( d[pos + 1] & 0xFF ) << 8 ) | ( d[pos] & 0xFF );
          Hex = String.format("%1$02X", d[pos] ) + " " + String.format("%1$02X", d[pos + 1] )+ " " + String.format("%1$02X", d[pos + 2] )+ " " + String.format("%1$02X", d[pos + 3] )
          + " " + String.format("%1$02X", d[pos + 4] )+ " " + String.format("%1$02X", d[pos + 5] )+ " " + String.format("%1$02X", d[pos + 6] )+ " " + String.format("%1$02X", d[pos + 7] );

          out += "<tr><td>Uncompressed file size.</td><td>" + Hex + "</td><td>" + val + "</td></tr>"; pos += 8; size -= 8;
        }

        if( size > 0 )
        {
          val = ( ( d[pos + 7] & 0xFF ) << 56 ) | ( ( d[pos + 6] & 0xFF ) << 48 ) | ( ( d[pos + 5] & 0xFF ) << 40 ) | ( ( d[pos + 4] & 0xFF ) << 32 ) |
          ( ( d[pos + 3] & 0xFF ) << 24 ) | ( ( d[pos + 2] & 0xFF ) << 16 ) | ( ( d[pos + 1] & 0xFF ) << 8 ) | ( d[pos] & 0xFF );
          Hex = String.format("%1$02X", d[pos] ) + " " + String.format("%1$02X", d[pos + 1] )+ " " + String.format("%1$02X", d[pos + 2] )+ " " + String.format("%1$02X", d[pos + 3] )
          + " " + String.format("%1$02X", d[pos + 4] )+ " " + String.format("%1$02X", d[pos + 5] )+ " " + String.format("%1$02X", d[pos + 6] )+ " " + String.format("%1$02X", d[pos + 7] );

          out += "<tr><td>Size of compressed data.</td><td>" + Hex + "</td><td>" + val + "</td></tr>"; pos += 8; size -= 8;
        }

        if( size > 0 )
        {
          val = ( ( d[pos + 7] & 0xFF ) << 56 ) | ( ( d[pos + 6] & 0xFF ) << 48 ) | ( ( d[pos + 5] & 0xFF ) << 40 ) | ( ( d[pos + 4] & 0xFF ) << 32 ) |
          ( ( d[pos + 3] & 0xFF ) << 24 ) | ( ( d[pos + 2] & 0xFF ) << 16 ) | ( ( d[pos + 1] & 0xFF ) << 8 ) | ( d[pos] & 0xFF );
          Hex = String.format("%1$02X", d[pos] ) + " " + String.format("%1$02X", d[pos + 1] )+ " " + String.format("%1$02X", d[pos + 2] )+ " " + String.format("%1$02X", d[pos + 3] )
          + " " + String.format("%1$02X", d[pos + 4] )+ " " + String.format("%1$02X", d[pos + 5] )+ " " + String.format("%1$02X", d[pos + 6] )+ " " + String.format("%1$02X", d[pos + 7] );

          out += "<tr><td>Offset to File signature.</td><td>" + Hex + "</td><td>" + val + "</td></tr>"; pos += 8; size -= 8;
        }

        if( size > 0 )
        {
          val = ( ( d[pos + 3] & 0xFF ) << 24 ) | ( ( d[pos + 2] & 0xFF ) << 16 ) | ( ( d[pos + 1] & 0xFF ) << 8 ) | ( d[pos] & 0xFF );
          Hex = String.format("%1$02X", d[pos] ) + " " + String.format("%1$02X", d[pos + 1] )+ " " + String.format("%1$02X", d[pos + 2] )+ " " + String.format("%1$02X", d[pos + 3] );

          out += "<tr><td>Offset to File signature.</td><td>" + Hex + "</td><td>" + val + "</td></tr>"; pos += 4; size -= 4;
        }
      }
      else if( CMD == 0x0000 )
      {
        while( CMD == 0x0000 && pos < d.length )
        {
          out += "<tr><td>Padding (0x0000).</td><td>" + String.format("%1$02X", CMD & 0xFF ) + "</td><td>Unused.</td></tr>";
          CMD = d[pos++];
        }
      }
      else
      {
        out += "<tr><td>Unknown (0x" + String.format("%1$04X", CMD ) + ").</td><td>" + Hex + "</td><td>" + CMD + "</td></tr>";

        int size = ( ( d[pos + 3] & 0xFF ) << 8 ) | ( d[pos + 2] & 0xFF ); Hex = String.format("%1$02X", d[pos + 2] ) + " " + String.format("%1$02X", d[pos + 3] );

        out += "<tr><td>Unknown data len.</td><td>" + Hex + "</td><td>" + size + "</td></tr>"; pos += 4;

        if( size > 0 )
        {
          Hex = ""; while( size > 0 ) { Hex += String.format("%1$02X", d[pos] ) + ( size > 1 ? " " : "" ); size -= 1; pos += 1; }

          out += "<tr><td>Unknown data.</td><td>" + Hex + "</td><td>?</td></tr>";
        }
      }
    }

    if( pos < d.length )
    {
      Hex = ""; int size = d.length - pos; while( size > 0 ) { Hex += String.format("%1$02X", d[pos] ) + ( size > 1 ? " " : "" ); size -= 1; pos += 1; }
      out += "<tr><td>Bad Data.</td><td>" + Hex + "</td><td>?</td></tr>";
    }

    //Display the result.

    file.Events = true; info( out + "</table></html>" );
  }*/

  //This event is called when the user clicks on an tree node.

  open: function(e)
  {
    var e = e.getArgs(), el = parseInt(e[0]);

    //Select file data bytes.

    if( el == 1 )
    {
      dModel.clear(); file.seek(parseInt(e[1])); ds.setType(15, 0, parseInt(e[2]));

      info.innerHTML = "<html>Extracting files from an zip is only supported by the application version.\r\nYou can use a zip application to extract the files if you wish to open or analyze them in the web version.</html>";
    }

    //Set descriptor.

    else if( el >= 2 ) { format.des[el-2].offset = parseInt(e[1]); dModel.setDescriptor(format.des[el-2]); }
  },

  //Multi pat file storage detail.

  multiPartZip: "<br /><br />We should always start at disk 0 and decompress the data into the file then move to disk 1 and so on adding data to the file.<br /><br />" +
  "This feature is only used in multi-part file storage.</html>",

  //Central directory.

  cDir: "<html>The central directory Has a copy of each file signature in this file and the location to each file signature.<br /><br />" +
  "The central directory has some additional attributes that can be used to add comments to files.<br /><br />" +
  "The central directory tells us which disk we are on, and allows us to do multi part zip files as well which is not included in the file signatures.<br /><br />" +
  "It is recommend that we read the central directory first and locate the file signatures using the offset given to the file signature.<br /><br />" +
  "This is because if we read only the file signatures we do not know if it is a multi-part file zip, or if more than one file signature exists for the same file and only one is the latest version of the file.</html>",

  //The ZIP file header.

  zipInfoData: [
    "<html>50 4B 03 04 is the start of a file (signature) in a compressed zip file.</html>",
    "<html>Version of zip used to create the file. The version number is convert to an decimal value.<br /><br />" +
    "in the case of version 122 it would mean 12.2v. In the case of 20 it means 2.0v.</html>",
    "<html>Version needed to extract (minimum). The version number is convert to an decimal value.<br /><br />" +
    "in the case of version 122 it would mean 12.2v. In the case of 20 it means 2.0v.</html>",
    "<html>The flag is meant to be viewed in binary. Each of the 16 binary digits if set one signifies an setting." +
    "The table bellow shows what setting each digit implies.<br /><br />" +
    "<table border='1'>" +
    "<tr><td>Digit</td><td>Description</td></tr>" +
    "<tr><td>0000000000001000</td><td>If this bit is set, the fields CRC-32, compressed size and uncompressed size are set to zero in the local header. The correct values are put in the data descriptor after the compressed data.</td></tr>" +
    "<tr><td>0000000000100000</td><td>If this bit is set, this indicates that the file is compressed patched data.</td></tr>" +
    "<tr><td>0000000001000000</td><td>Strong encryption. If this bit is set, you MUST set the version needed to extract value to at least 50 and you MUST also set bit 0. If AES encryption is used, the version needed to extract value MUST be at least 51.</td></tr>" +
    "<tr><td>0000100000000000</td><td>Language encoding flag (EFS).</td></tr>" +
    "<tr><td>0010000000000000</td><td>Set when encrypting the Central Directory.</td></tr>" +
    "</table></html>",
    "<html>Compression method.<br /><br />" +
    "<table border='1'>" +
    "<tr><td>Value</td><td>Compression</td></tr>" +
    "<tr><td>0</td><td>The file is stored (no compression).</td></tr>" +
    "<tr><td>1</td><td>The file is Shrunk.</td></tr>" +
    "<tr><td>2</td><td>The file is Reduced with compression factor 1.</td></tr>" +
    "<tr><td>3</td><td>The file is Reduced with compression factor 2.</td></tr>" +
    "<tr><td>4</td><td>The file is Reduced with compression factor 3.</td></tr>" +
    "<tr><td>5</td><td>The file is Reduced with compression factor 4.</td></tr>" +
    "<tr><td>6</td><td>The file is Imploded.</td></tr>" +
    "<tr><td>7</td><td>Reserved for Tokenizing compression algorithm.</td></tr>" +
    "<tr><td>8</td><td>The file is Deflated.</td></tr>" +
    "<tr><td>9</td><td>Enhanced Deflating using Deflate64(tm).</td></tr>" +
    "<tr><td>10</td><td>PKWARE Data Compression Library Imploding (old IBM TERSE).</td></tr>" +
    "<tr><td>11</td><td>Reserved by PKWARE.</td></tr>" +
    "<tr><td>12</td><td>File is compressed using BZIP2 algorithm.</td></tr>" +
    "<tr><td>13</td><td>Reserved by PKWARE.</td></tr>" +
    "<tr><td>14</td><td>LZMA.</td></tr>" +
    "<tr><td>15</td><td>Reserved by PKWARE.</td></tr>" +
    "<tr><td>16</td><td>IBM z/OS CMPSC Compression.</td></tr>" +
    "<tr><td>17</td><td>Reserved by PKWARE.</td></tr>" +
    "<tr><td>18</td><td>File is compressed using IBM TERSE (new).</td></tr>" +
    "<tr><td>19</td><td>IBM LZ77 z Architecture.</td></tr>" +
    "<tr><td>20</td><td>Deprecated (use method 93 for zstd).</td></tr>" +
    "<tr><td>93</td><td>Zstandard (zstd) Compression.</td></tr>" +
    "<tr><td>94</td><td>MP3 Compression.</td></tr>" +
    "<tr><td>95</td><td>XZ Compression.</td></tr>" +
    "<tr><td>96</td><td>JPEG variant.</td></tr>" +
    "<tr><td>97</td><td>WavPack compressed data.</td></tr>" +
    "<tr><td>98</td><td>PPMd version I, Rev 1.</td></tr>" +
    "<tr><td>99</td><td>AE-x encryption marker.</td></tr>" +
    "</table></html>",
    "<html>File last modification time.</html>",
    "<html>File last modification date.</html>",
    "<html>CRC-32 of uncompressed data. This is the number of zeros that should exist in the binary file.<br /><br />" +
    "If the CRC does not match the count of zeros in binary in the file we know there is something wrong.</html>",
    "<html>Compressed size. This is the size of the data after this PK signature.<br /><br />" +
    "After the compressed data should be another PK signature.<br /><br />" +
    "If the value is FF FF FF FF hex then the value is stored using a 64 bit number under the extra data field.</html>",
    "<html>Uncompressed file size. This is the file size after we decompress the file. In some cases this is 0 as it is a folder.<br /><br />" +
    "If the value is FF FF FF FF hex then the value is stored using a 64 bit number under the extra data field.</html>",
    "<html>File name length in bytes.</html>",
    "<html>Extra field length in bytes. The extra felid is useful for extending the file attributes and properties.<br /><br />" +
    "The extra data felid is used to extend the zip file format.</html>",
    "<html>Comment length in bytes.</html>",
    "<html>Disk Number.",
    "<html>Internal attributes.</html>",
    "<html>External attributes.</html>",
    "<html>File signature location.</html>",
    "<html>The zip file format uses the full path to the file then name of the file.</html>"
  ],

  //Data descriptor.

  dataInfoData: [
    "<html>This is the data descriptor signature. Marks the end of a compressed file data.</html>",
    "<html>CRC-32 of uncompressed data. This is the number of zeros that should exist in the binary file.<br /><br />" +
    "If the CRC does not match the count of zeros in binary in the file we know there is something wrong.</html>",
    "<html>Compressed size. This is the size of the data before this data signature.</html>",
    "<html>Uncompressed file size. This is the file size after we decompress the file.</html>"
  ],

  loc64InfoData: [
    "<html>Zip64 end of central dir locator signature.</html>",
    "<html>Total number of disks that use zip 64 signatures.",
    "<html>The offset to the zip64 end of central directory record. If this does not match the location the signature was read then there is most likely file corruption.</html>",
    "<html>Total number of disks that this zip file data is split into."
  ],

  endInfoData: [
    "<html>End of central dir signature.</html>",
    "<html>The size of this signature.<br /><br />" +
    "If this is set larger than 44 bytes then the rest of the bytes after the signature are used as an extended data failed.<br /><br />" +
    "The extended data field is reserved for future use.</html>",,,
    "<html>The current disk number.",
    "<html>Number of disk with the same central directory.",
    "<html>Total number of entries in the central directory on this disk.",
    "<html>Total number of entries in the central directory across all disks.",
    "<html>Size of the central directory in this file.</html>",
    "<html>Offset to start location for the central directory in this file.</html>",
    "<html>File user comment length.</html>",
    "<html>File user comment.</html>"
  ],

  zipInfo: function(i)
  {
    i = i > 0 ? ( i > 10 ? i + 6 : i + 1 ) : i;

    if( i < 0 )
    {
      var pos = file.offset-file.data.offset;
      this.fName.length(file.data[pos+26] | (file.data[pos+27]<<8));
      this.dFelid.length(file.data[pos+28] | (file.data[pos+29]<<8));
      
      info.innerHTML = "<html>All files in the zip begin with a PK signature. The file compressed data is right after the PK parameters.<br /><br />" +
      "The next file signature is after the compressed file size parameter.<br /><br />" +
      "In some cases a signature code (data descriptor) is used to identify the end of the compressed file data in some cases.<br /><br />" +
      "The data descriptor tells us how many bytes the compressed data is which should match the number of bytes we read after the PK parameters.<br /><br />" +
      "Most of the time only PK signatures exist and the number of bytes for the compressed file is set in the PK header.<br /><br />" +
      "The only time we do not set the compressed file size in the PK header is when we do not know the compressed file size till after the file was compressed.<br /><br />" +
      "The flag parameter can also be adjusted to signify that the data descriptor marks the end of the files data.</html>";
    }
    else if( i == 18 )
    {
      info.innerHTML = "Unsupported at this time."; //this.extendedData();
    }
    else
    {
      info.innerHTML = this.zipInfoData[i];
    }
  },

  dataInfo: function(i)
  {
    if( i < 0 )
    {
      info.innerHTML = "<html>In the case that the data descriptor setting is set in the PK header then the size of the compressed file was not known.<br /><br />" +
      "Instead the Data descriptor signature marks the end of the files data.<br /><br />" +
      "The Data descriptor tells us how big the compressed file is which should match the number of bytes we read before encountering the data descriptor signature.<br /><br />" +
      "The data descriptor also stores the files original size, and has an CRC count which is numbers of zero digits that should exist in the file once decompress.<br /><br />" +
      "The CRC is very important as it can be used to know if the decompressed file matches the original.</html>";
    }
    else
    {
      info.innerHTML = this.dataInfoData[i];
    }
  },

  dirInfo: function(i)
  {
    if( i < 0 )
    {
      info.innerHTML = this.cDir;
    }
    else if( i == 0 )
    {
      info.innerHTML = "<html>50 4B 01 02 is the start of a file signature in the central directory in an zip file.</html>";
    }
    else if( i == 18 )
    {
      info.innerHTML = "Unsupported at this time."; //this.extendedData();
    }
    else if( i < 18 )
    {
      info.innerHTML = this.zipInfoData[i];
    }
  },

  loc64Info: function(i)
  {
    if( i < 0 )
    {
      info.innerHTML = "<html>This is used as the location to the directory end 64 signature. It is not needed, but is used to check for errors while reading.<br /><br />" +
      "If existent and the Directory end 64 signature that was read does not match the offset then there is most likely data corruption.</html>";
    }
    else
    {
      info.innerHTML = this.loc64InfoData[i];
    }
  },

  end64Info: function(i)
  {
    if( i < 0 )
    {
      info.innerHTML = "<html>The end of zip may specify more than one zip file as a disk." + this.multiPartZip;
    }
    else
    {
      info.innerHTML = i < 10 ? this.endInfoData[i] : "<html>The extra data field is reserved for future use.</html>";
    }
  },

  endInfo: function(i)
  {
    if( i < 0 )
    {
      info.innerHTML = "<html>The end of zip may specify more than one zip file as a disk." + this.multiPartZip;
    }
    else
    {
      info.innerHTML = this.endInfoData[ i > 0 ? i + 3 : i ];
    }
  }
}