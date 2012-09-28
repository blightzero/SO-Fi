/**
 *  This program is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free Software
 *  Foundation; either version 3 of the License, or (at your option) any later
 *  version.
 *  You should have received a copy of the GNU General Public License along with
 *  this program; if not, see <http://www.gnu.org/licenses/>.
 *  Use this application at your own risk.
 *
 *  Copyright (c) 2012 by Benjamin Grap.
 */


package edu.comsys.so_fi_legacy;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.Random;

import android.util.Log;




public class Sofi_hashConversion {

   
    /** Special character "z" stands for four NULL bytes (short-cut for !!!!!) */
    public static final int ZERO          = 0x7A; //"z"
    /** ZERO as a byte array */
    public static final byte[] ZERO_ARRAY = {(byte)ZERO};
    /** The start index for ASCII85 characters (!) */
    public static final int START         = 0x21; //"!"
    /** The end index for ASCII85 characters (u) */
    public static final int END           = 0x75; //"u"
    /** The EOL indicator (LF) */
    public static final int EOL           = 0x0A; //"\n"
    /** The EOD (end of data) indicator */
    public static final byte[] EOD        = {0x7E, 0x3E}; //"~>"
    
    /** Array of powers of 85 (4, 3, 2, 1, 0) */
    public static final long POW85[] = new long[] {85 * 85 * 85 * 85, 85 * 85 * 85, 85 * 85, 85, 1};

    

	Sofi_hashConversion(){
		
	}
	
	public String xorString(String data, String key){
		StringBuilder sb = new StringBuilder();
		for(int i=0; i<data.length() && i<key.length();i++)
		    sb.append((char)(data.charAt(i) ^ key.charAt(i)));
		return sb.toString();
	}
	
	public byte [] xorBytes(byte [] data, byte [] key){
		byte [] result = new byte[data.length];
		for(int i=0; i<data.length && i<key.length;i++){
			result[i] = (Byte)(byte)(data[i] ^ key[i]);
		}
		return result;
	}
	
	public String sanitize(String input){
		StringBuilder res = new StringBuilder();
		char [] s = input.toCharArray();
		
		for(char c : s){
			
			if(res.length()>0 && res.lastIndexOf("_")==res.length()){ //Have at most one consecutive underscore.
				continue;
			}else if(c==' ' || c=='-' || c=='_' || c=='.'){ //Characters which are converted to underscores.
				res.append('_');
			}else if((int)c > 128){ //Skip NON-ASCII Characters in String
				continue;
			}else{ //convert everything to lower case Characters.
				res.append(Character.toLowerCase(c));
			}
			
		}
		
		return res.toString();
	}
	
	public String san_enc_md5_b85(String s){
		String encoded = null;
		s = sanitize(s);
		byte[] bytes = encode_md5(s);
		encoded = encode_b85(bytes);
		return encoded;
	}
	
	public String encode_md5_b85(String s){
		String encoded = null;
		byte[] bytes = encode_md5(s);
		encoded = encode_b85(bytes);
		return encoded;
	}
	
	public static byte[] encode_md5(String s){
		byte[] bytesOfMessage;
		try {
			bytesOfMessage = s.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return null;
		}
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		byte[] thedigest = md.digest(bytesOfMessage);
		return thedigest;
	}
	
	public static byte[] encode_sha1(String s){
		byte[] bytesOfMessage;
		try {
			bytesOfMessage = s.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return null;
		}
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		byte[] thedigest = md.digest(bytesOfMessage);
		return thedigest;
	}
	
	public static byte[] encode_sha1(byte [] bytesOfMessage){
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		byte[] thedigest = md.digest(bytesOfMessage);
		return thedigest;
	} 
	
	public static byte[][] trippleHash(String s){
		byte[][] hashList= new byte[3][];
		
		hashList[0] = encode_sha1(s);
		hashList[1] = encode_sha1(hashList[0]);
		hashList[2] = encode_sha1(hashList[1]);
		
		return hashList;
	}
	
	public static String encodeASCII85(byte[] b, int off, int len) {
	    long i = 0;
	    StringBuffer s = new StringBuffer();
	    //s.append("<~");
	    while (len >= 4) {
	      i = ((b[off] & 0xFFL) << 24L) | ((b[off+1] & 0xFFL) << 16L) | ((b[off+2] & 0xFFL) << 8L) | (b[off+3] & 0xFFL);
	      if (i == 0) {
	        s.append('z');
	      } else {
	        s.append((char)('!' + ((i / 52200625) % 85)));
	        s.append((char)('!' + ((i / 614125) % 85)));
	        s.append((char)('!' + ((i / 7225) % 85)));
	        s.append((char)('!' + ((i / 85) % 85)));
	        s.append((char)('!' + (i % 85)));
	      }
	      off += 4;
	      len -= 4;
	    }
	    switch (len) {
	    case 3:
	      i = ((b[off] & 0xFFL) << 24L) | ((b[off+1] & 0xFFL) << 16L) | ((b[off+2] & 0xFFL) << 8L);
	      s.append((char)('!' + ((i / 52200625) % 85)));
	      s.append((char)('!' + ((i / 614125) % 85)));
	      s.append((char)('!' + ((i / 7225) % 85)));
	      s.append((char)('!' + ((i / 85) % 85)));
	      break;
	    case 2:
	      i = ((b[off] & 0xFFL) << 24L) | ((b[off+1] & 0xFFL) << 16L);
	      s.append((char)('!' + ((i / 52200625) % 85)));
	      s.append((char)('!' + ((i / 614125) % 85)));
	      s.append((char)('!' + ((i / 7225) % 85)));
	      break;
	    case 1:
	      i = ((b[off] & 0xFFL) << 24L);
	      s.append((char)('!' + ((i / 52200625) % 85)));
	      s.append((char)('!' + ((i / 614125) % 85)));
	      break;
	    }
	    //s.append("~>");
	    return s.toString();
	  }
	
	  public static String encodeASCII85(byte[] b) {
		  return encodeASCII85(b, 0, b.length);
	  }

	  public static String encode_b85(byte [] b){
		  return encodeASCII85(b, 0, b.length);
	  }

	  public static byte[] decode_b85(String s){
		  return decodeASCII85(s);
	  }
	  
	  public static byte[] decodeASCII85(String s) {
		  s = s.trim();
			if (s.startsWith("<~") && s.endsWith("~>")) {
			  s = s.substring(2, s.length()-2).trim();
			}
			CharacterIterator it = new StringCharacterIterator(s);
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			long i = 0; int j = 0;
			for (char ch = it.first(); ch != CharacterIterator.DONE && ch != '~'; ch = it.next()) {
			  if (ch == 'z' && j == 0) {
			    out.write(0);
			    out.write(0);
			    out.write(0);
			    out.write(0);
			  } else if (ch == 'y' && j == 0) {
			    out.write(' ');
			    out.write(' ');
			    out.write(' ');
			    out.write(' ');
			  } else if (ch == 'x' && j == 0) {
			    out.write(-1);
			    out.write(-1);
			    out.write(-1);
			    out.write(-1);
			  } else if (ch >= '!' && ch <= 'u') {
			    i = i * 85L + (long)(ch - '!');
			    j++;
			    if (j >= 5) {
			      out.write((int)(i >> 24L));
			      out.write((int)(i >> 16L));
			      out.write((int)(i >> 8L));
			      out.write((int)i);
			      i = 0; j = 0;
			    }
			  }
			}
			switch (j) {
			case 4:
			  i = i * 85L + 84L;
			  out.write((int)(i >> 24L));
			  out.write((int)(i >> 16L));
			  out.write((int)(i >> 8L));
			  break;
			case 3:
			  i = i * 85L + 84L;
			  i = i * 85L + 84L;
			  out.write((int)(i >> 24L));
			  out.write((int)(i >> 16L));
			  break;
			case 2:
			  i = i * 85L + 84L;
			  i = i * 85L + 84L;
			  i = i * 85L + 84L;
			  out.write((int)(i >> 24L));
			  break;
			}
			return out.toByteArray();
	  }
}

class ssid {
	private static final String SSID_PREFIX = "#;";

	private byte [] hash = {};
	private String SSID;
	private boolean Native = false;
	private int Service = 2;
	private boolean Private = false;
	private boolean Request = true;
	private boolean Reply = false;
	private int BitSize = 5;
	private int Comid = 0;

	
	
	/**
	 * Contructor, with Hash and Config of SSID.
	 * 
	 * @param hashString
	 * @param Native
	 * @param Private
	 * @param Request
	 * @param Reply
	 * @param Service
	 * @param Comid
	 * @param BitSize
	 */
	ssid(byte [] hashString, boolean Native, boolean Private, boolean Request, boolean Reply, int Service, int Comid, int BitSize){
		this.hash = hashString;
		this.Native = Native;
		this.Private = Private;
		this.Request = Request;
		this.Reply = Reply;
		this.Service = Service;
		this.Comid = Comid;
		this.BitSize = BitSize;
		this.SSID = this.toString();
	}
	
	/**
	 * Constructor from existing SSID.
	 * @param SSID
	 */
	ssid(String SSID){
		this.fromString(SSID);
	}
	
	/**
	 * Default Constructor for Emtpy SSID.
	 */
	ssid(){
		this.hash = Sofi_hashConversion.encode_sha1("0000000000000000");
		this.Native = false;
		this.Service = 2;
		this.Private = false;
		this.Request = true;
		this.Reply = false;
		this.BitSize = 5;
		this.Comid = 0;
		this.SSID = this.toString();
	}
	
	/**
	 * Convert String that was received back to an SSID Object. 
	 * @param SSID
	 */
	public void fromString(String SSID){
		byte [] flags;
		this.SSID = SSID;
		SSID = SSID.substring(2);
		flags = Sofi_hashConversion.decode_b85(SSID.substring(0, 6));
		this.Native = ((int)(flags[0] & 128)) == 128;
		this.Private = ((int)(flags[0] & 64)) == 64;
		this.Request = ((int)(flags[0] & 32)) == 32;
		this.Reply = ((int)(flags[0] & 16)) == 16;
		this.BitSize = (int)(flags[0]&15);
		this.Service = (int) flags[1];
		this.Comid = (int) (flags[3] & 0xFF);
		this.hash = Sofi_hashConversion.decode_b85(SSID.substring(5));
	}
	
	public boolean isNative(){
		return this.Native;
	}
	
	public boolean isPublic(){
		return !this.Private;
	}
	
	public boolean isRequest(){
		return this.Request;
	}
	
	public boolean isReply(){
		return this.Reply;
	}
	
	public int getID(){
		return this.Comid;
	}
	
	public int getService(){
		return this.Service;
	}
	
	public byte [] getHash(){
		return this.hash;
	}
	
	public int getBitSize(){
		return this.BitSize;
	}
	
	/**
	 * returns the finished SSID
	 */
	public String toString(){
		byte [] flag = new byte[4];
		this.SSID = SSID_PREFIX;
		flag[0] = (byte)(((this.Native? 1 : 0)<<7)+((this.Private? 1 : 0)<<6)+((this.Request? 1 : 0)<<5)+((this.Reply? 1 : 0)<<4)+this.BitSize);
		flag[1] = (byte)this.Service;
		flag[2] = (byte) 32;
		flag[3] = (byte) this.Comid;
		this.SSID = this.SSID + Sofi_hashConversion.encode_b85(flag) + Sofi_hashConversion.encode_b85(this.hash);
		return this.SSID;
	}
}






class puzzle{
	/**
	 * NumSubPuz * SolSize must result in 20! 
	 */
	public final static int NumSubPuz = 5;
	public final static int SolSize = 4;
	
	public byte [] puzzle;
	public int bitSize;
	
	puzzle(byte [] puzzle, int bitSize){
		if(puzzle.length == (NumSubPuz * SolSize)){
			this.puzzle = puzzle;
			this.bitSize = bitSize;
		}else{
			this.puzzle = new byte[20];
			this.bitSize = 0;
		}
	}
	
	public boolean isValid(){
		int crc1, crc2;

		
		crc1 = CRC16(this.puzzle);
		crc2 = (puzzle[18] <<8 & puzzle[19]);
		
		if(crc1 == crc2){
			return true;
		}else{
			return false;
		}
	}
	
	public byte [] getSolution(){
		byte [] solution = new byte [NumSubPuz * SolSize];
		byte [][] sol = new byte [NumSubPuz][];
		int offset = 0;
		
		for(int i = 0; i < NumSubPuz;i++){
			sol[i] = solveSubPuzzle(i);
			System.arraycopy(sol[i], 0, solution, offset, sol[i].length);
			offset += sol[i].length;
		}
		return solution;
	}
	
	private byte [] solveSubPuzzle(int SubNo){
		Random randgen = new Random();
		byte [] solution = {0,0,0,0};
		
		while(!isSolution(solution,(byte)SubNo)){
			randgen.nextBytes(solution);
		}
		
		return solution;
	}
	
	private boolean isSolution(byte [] solution,byte SubNo){
		byte [] psol;
		byte [] asol = {SubNo};
		byte [] bsol = new byte[puzzle.length + solution.length + 1];
		int i;
		
		System.arraycopy(puzzle, 0, bsol, 0, puzzle.length);
		System.arraycopy(asol, 0, bsol, puzzle.length, asol.length);
		System.arraycopy(solution, 0, bsol, puzzle.length + asol.length, solution.length);
		psol = Sofi_hashConversion.encode_sha1(bsol);
		Log.d("SOFI-PUZZLE",new String(asol));
		i=0;
		while( ((int)psol[i/8] & (1 << 7-(i%8))) == ((int)puzzle[i/8] & (1 << 7-(i%8))) ){
			i++;
		}
		return (i>=this.bitSize);
	}
	
    public int CRC16(byte [] bytes) { 

        int[] table = {
            0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
            0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
            0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
            0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
            0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
            0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
            0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
            0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
            0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
            0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
            0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
            0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
            0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
            0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
            0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
            0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
            0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
            0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
            0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
            0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
            0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
            0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
            0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
            0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
            0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
            0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
            0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
            0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
            0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
            0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
            0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
            0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
        };
        int crc = 0x0000;
        for (byte b : bytes) {
            crc = (crc >>> 8) ^ table[(crc ^ b) & 0xff];
        }
        return crc;
    }
}
