//----------------------------------------------------------------------------//
//  active when finished loading                                              //
//----------------------------------------------------------------------------//
$(document).ready(function(){

	/* 
	 * send shellcode
	 */
	$('button').on('click', function () {
		var thisID = $(this).attr('id');
		var baseID = thisID.replace("_selectshell","");
		
		/* no Input and Button */
		if(!thisID.match(/_selectshell$/)) {
			//alert('wrong ID: '+thisID); // DEBUG!!!
			return;
		}

		/* get text input */
		var name = $('#'+baseID+'_name').val();
		var host = $('#'+baseID+'_host').val();
		var port = $('#'+baseID+'_port').val();
		var textarea = $('#'+baseID+'_textarea');
		if (textarea != null) {
		  textarea = textarea.val()
		}

		/* get radio */
    var radioval = $("input[name='"+baseID+"_system']:checked").val();
		
		/* get checkbox */
    var xor = document.getElementById(baseID+'_xor').checked;  // return true|false
		
		/* disable button */
		$('#'+thisID).addClass("disabled");
		
		/* create xmlhttp object */
		var xmlhttp=new XMLHttpRequest();
		
		/* set onreadystatechange function */
		xmlhttp.onreadystatechange=function() {
			if (xmlhttp.readyState==4 && xmlhttp.status==200) {
				// enable button
				$('#'+thisID).removeClass("disabled");
				// alert server request
				resttxt = xmlhttp.responseText;
				if("OK" != resttxt) {
					alert(resttxt);
				}else {
				  window.location.reload(); 
				}
			}
		}
		
		/* send request */
		xmlhttp.open("POST","/api/set/shell",true);
		xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
		xmlhttp.send("name="+name+"&host="+host+"&port="+port+"&system="+radioval+"&shellselect="+baseID+"&textarea="+textarea+"&xor="+xor);
	})//-------------------------------------------------

});
