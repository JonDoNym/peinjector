package eu.peinjector.libpe;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * This class interprets the config-string returned by the server.
 */
public class LibPeServerConfig {

	
	// Class variables
	// ------------------------------------------------------------------------------
	private Properties config = new Properties();
	/**
	 * The original string that came back from the server.
	 */
	public final String originalServerIni;
	/**
	 * <b>true:</b> The configuration has been successfully loaded and contains values.<br>
	 * <b>false:</b> The configuration is empty. There are returned invalid values.<br>
	 */
	public final boolean validConfig;
	
	
	// Constructors
	// ------------------------------------------------------------------------------
	/**
	 * Interprets the string as INI configuration
	 */
	public LibPeServerConfig(String serverconfigini) {
		// set originalServerIni String
		this.originalServerIni = serverconfigini;
		
		// load Properties
		if (null != serverconfigini) {
			try {
				InputStream stream = new ByteArrayInputStream(serverconfigini.getBytes(StandardCharsets.UTF_8));
				config.load(stream);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		// is valid config (maybe)?
		if(!config.isEmpty()) {
			// is NOT empty -> OK
			validConfig = true;
		}else {
			// is empty  :*(
			validConfig = false;
		}
	}

	
	// general (intern) methods
	// ------------------------------------------------------------------------------
	/**
	 * convert and return the option as boolean
	 * @return true (value=1 or value=true)
	 */
	private boolean getBoolean(String key) {
		Object value = config.get(key);
		if(value == null) {
			System.err.println(LibPeServerConfig.class +": '"+ key +"' not found!");
			return false;
		} else {
			if(value.toString().equals("1") || value.toString().toLowerCase().equals("true")) {
				return true;
			} else {
				return false;
			}
		}
	}
	
	/**
	 * convert and return the option as string
	 * @return value (null -> "")
	 */
	private String getString(String key) {
		Object value = config.get(key);
		if(value == null) {
			System.err.println(LibPeServerConfig.class +": '"+ key +"' not found!");
			return "";
		} else {
			return value.toString();
		}
	}
	
	/**
	 * convert and return the option as integer
	 * @param key
	 * @return
	 */
	private int getInt(String key) {
		Object value = config.get(key);
		if(value == null) {
			System.err.println(LibPeServerConfig.class +": '"+ key +"' not found!");
			return 0;
		} else {
			try {
				return Integer.valueOf(value.toString());
			} catch (Exception e) {
				return 0;
			}
		}
	}
	
	
	// Getter and Setter
	// ------------------------------------------------------------------------------
	/**
	 * @see LibPeControlProtocol#cmdSendSetRandomSectionName(boolean)
	 */
	public boolean isSection_name_random() {
		return getBoolean("section_name_random");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetPayloadNameX86(String)
	 */
	public String getPayload_name_x86() {
		return getString("payload_name_x86");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetPayloadNameX64(String)
	 */
	public String getPayload_name_x64() {
		return getString("payload_name_x64");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetMethodAlignment(boolean)
	 */
	public boolean isMethod_alignment() {
		return getBoolean("method_alignment");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetMethodAlignmentResize(boolean)
	 */
	public boolean isMethod_alignment_resize() {
		return getBoolean("method_alignment_resize");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetMethodNewSection(boolean)
	 */
	public boolean isMethod_new_section() {
		return getBoolean("method_new_section");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetMethodChangeFlags(boolean)
	 */
	public boolean isMethod_change_flags() {
		return getBoolean("method_change_flags");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetMethodCrossSectionJump(boolean)
	 */
	public boolean isMethod_cross_section_jump() {
		return getBoolean("method_cross_section_jump");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetMethodCrossSectionJumpIterations(int)
	 */
	public int getMethod_cross_section_jump_iterations() {
		return getInt("method_cross_section_jump_iterations");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetEncrypt(boolean)
	 */
	public boolean isEncrypt() {
		return getBoolean("encrypt");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetEncryptIterations(int)
	 */
	public int getEncrypt_iterations() {
		return getInt("encrypt_iterations");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetRemoveIntegrityCheck(boolean)
	 */
	public boolean isRemove_integrity_check() {
		return getBoolean("remove_integrity_check");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetTryStayStealth(boolean)
	 */
	public boolean isTry_stay_stealth() {
		return getBoolean("try_stay_stealth");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetEnable(boolean)
	 */
	public boolean isEnable() {
		return getBoolean("enable");
	}

	/**
	 * If this value is true, then no port can be changed. 
	 * (server-side locked)
	 */
	public boolean isPersistent_ports() {
		return getBoolean("persistent_ports");
	}

	/**
	 * return the token (byte[]) as HEX-String
	 * @see LibPeControlProtocol#cmdSendSetToken(byte[])
	 */
	public String getToken() {
		return getString("token");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetDataPort(int)
	 * @see #isPersistent_ports()
	 */
	public int getData_port() {
		return getInt("data_port");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetDataInterface(boolean)
	 */
	public boolean isData_interface() {
		return getBoolean("data_interface");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetControlPort(int)
	 * @see #isPersistent_ports()
	 */
	public int getControl_port() {
		return getInt("control_port");
	}

	/**
	 * @see LibPeControlProtocol#cmdSendSetControlInterface(boolean)
	 */
	public boolean isControl_interface() {
		return getBoolean("control_interface");
	}

	/**
	 * Returns the number of infected files. (x86)
	 */
	public int getInfection_counter_x86() {
		return getInt("infection_counter_x86");
	}

	/**
	 * Returns the number of infected files. (x64)
	 */
	public int getInfection_counter_x64() {
		return getInt("infection_counter_x64");
	}

}
