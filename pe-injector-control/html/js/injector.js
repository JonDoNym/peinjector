//----------------------------------------------------------------------------//
//  active when finished loading                                              //
//----------------------------------------------------------------------------//
$(document).ready(function(){
	
	/* 
	 * ON-OFF-Button function
	 * 
	 * Example: Button-Group for 'xxxxx'
	 *        <div class="btn-group">
	 *          <button type="button" id="xxxxx_ON" class="btn btn-success disabled">ON</button>
	 *          <button type="button" id="xxxxx_OFF" class="btn btn-danger disabled">OFF</button>
	 *        </div>
	 *
	 */
	$('button').on('click', function () {
		var thisID = $(this).attr('id');
		var baseID = thisID.replace("_ON","").replace("_OFF","");
		
		/* no ON/OFF Button? => return */
		if(!thisID.match(/_ON$/) && !thisID.match(/_OFF$/)) {
			//alert('wrong ID: '+thisID); // DEBUG!!!
			return;
		}

		/* determine the new status */
		var state = false;
		if(thisID.match(/_ON$/)) {
			state = true;
		}
		
		/* disable the button */
		setOnOffButtons(baseID, "disabled");
		
		/* create xmlhttp object */
		var xmlhttp=new XMLHttpRequest();
		
		/* set onreadystatechange function */
		xmlhttp.onreadystatechange=function() {
			if (xmlhttp.readyState==4 && xmlhttp.status==200) {
				// set the button to the new state
				setOnOffButtons(baseID, state);
				// alert server request
				resttxt = xmlhttp.responseText;
				if("OK" != resttxt) {
					alert(resttxt);
				}
			}
		}
		
		/* send request */
		xmlhttp.open("POST","/api/set/boolean",true);
		xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
		xmlhttp.send("key="+baseID+"&value="+state);
		

	})//-------------------------------------------------
	
	/* 
	 * LOCAL-GLOBAL-Button function
	 * 
	 * Example: Button-Group for 'yyyyy'
	 *        <div class="btn-group">
	 *          <button type="button" id="yyyyy_LOCAL" class="btn btn-info disabled">local</button>
	 *          <button type="button" id="yyyyy_GLOBAL" class="btn btn-warning disabled">global</button>
	 *        </div>
	 *
	 */
	$('button').on('click', function () {
		var thisID = $(this).attr('id');
		var baseID = thisID.replace("_LOCAL","").replace("_GLOBAL","");
		
		/* no LOCAL/GLOBAL Button */
		if(!thisID.match(/_LOCAL$/) && !thisID.match(/_GLOBAL$/)) {
			//alert('wrong ID: '+thisID); // DEBUG!!!
			return;
		}

		/* determine the new status */
		var state = false;
		if(thisID.match(/_LOCAL$/)) {
			state = true;
		}
		
		/* disable the button */
		setLocalGlobalButtons(baseID, "disabled");
		
		/* create xmlhttp object */
		var xmlhttp=new XMLHttpRequest();
		
		/* set onreadystatechange function */
		xmlhttp.onreadystatechange=function() {
			if (xmlhttp.readyState==4 && xmlhttp.status==200) {
				// set the button to the new state
				setLocalGlobalButtons(baseID, state);
				// alert server request
				resttxt = xmlhttp.responseText;
				if("OK" != resttxt) {
					alert(resttxt);
				}
			}
		}
		
		/* send request */
		xmlhttp.open("POST","/api/set/localglobal",true);
		xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
		xmlhttp.send("key="+baseID+"&value="+state);
	})//-------------------------------------------------
	
	/* 
	 * Text-Input-and-Button function
	 * 
	 * Example: Form-Group for 'zzzzz'
   *        <div class="input-group">
   *          <input type="number" id="zzzzz_TXT1" class="form-control" placeholder="loading..." min="1" max="65535">
   *          <span class="input-group-btn">
   *            <button type="button" id="zzzzz_TXT2" class="btn btn-default"><span class="glyphicon glyphicon-floppy-disk" aria-hidden="true"></span> Save</button>
   *          </span>
   *        </div>
	 *
	 */
	$('button').on('click', function () {
		var thisID = $(this).attr('id');
		var baseID = thisID.replace("_TXT2","");
		
		/* no Input and Button */
		if(!thisID.match(/_TXT2$/)) {
			//alert('wrong ID: '+thisID); // DEBUG!!!
			return;
		}

		/* get text */
		var txt = $('#'+baseID+'_TXT1').val();
		
		/* disable button */
		$('#'+baseID+'_TXT2').addClass("disabled");
		
		/* create xmlhttp object */
		var xmlhttp=new XMLHttpRequest();
		
		/* set onreadystatechange function */
		xmlhttp.onreadystatechange=function() {
			if (xmlhttp.readyState==4 && xmlhttp.status==200) {
				// enable button
				$('#'+baseID+'_TXT2').removeClass("disabled");
				// alert server request
				resttxt = xmlhttp.responseText;
				if("OK" != resttxt) {
					alert(resttxt);
				}
			}
		}
		
		/* send request */
		xmlhttp.open("POST","/api/set/text",true);
		xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
		xmlhttp.send("key="+baseID+"&value="+txt);
	})//-------------------------------------------------
	
//___________________________________________________________________
	/*
	 * the INJECTOR_RESTART_BUTTON !
	 */
	$('#inj_restart_button').on('click', function () {
		/* create xmlhttp object */
		var xmlhttp=new XMLHttpRequest();
		
		/* set onreadystatechange function */
		xmlhttp.onreadystatechange=function() {
			if (xmlhttp.readyState==4 && xmlhttp.status==200) {
				resttxt = xmlhttp.responseText;
				if("OK" != resttxt) {
					alert(resttxt);
				}else {
					// restart command received
					window.location.reload();  
				}
			}
		}
		
		/* send request */
		xmlhttp.open("POST","/api/set/event",true);
		xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
		xmlhttp.send("key=injrestart&value=void");
	})//-------------------------------------------------
	
	/*
	 * the INJECTOR_EXPORT_BUTTON !
	 */
	$('#inj_export_button').on('click', function () {
		/* create xmlhttp object */
		var xmlhttp=new XMLHttpRequest();
		
		/* set onreadystatechange function */
		xmlhttp.onreadystatechange=function() {
			if (xmlhttp.readyState==4 && xmlhttp.status==200) {
				resttxt = xmlhttp.responseText;
				// generate download
        var pom = document.createElement('a');
        pom.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(resttxt));
        pom.setAttribute('download', 'injector_config.ini');
        pom.style.display = 'none';
        document.body.appendChild(pom);
        pom.click();
        document.body.removeChild(pom);
			}
		}
		
		/* send request */
		xmlhttp.open("POST","/api/export",true);
		xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
		xmlhttp.send("key=exportconfig&value=void");
	})//-------------------------------------------------
	
	/*
	 * the INJECTOR_IMPORT_BUTTON !
	 */
	$('#inj_import_button').on('click', function () {
		/* send */
		alert("TODO: send INJECTOR import!");
	})//-------------------------------------------------
	
	/*
	 * Token generate BUTTON
	 */
	$('button').on('click', function () {
		var thisID = $(this).attr('id');
		var baseID = thisID.replace("_GEN","");
		
		/* no Input and Button */
		if(!thisID.match(/_GEN$/)) {
			//alert('wrong ID: '+thisID); // DEBUG!!!
			return;
		}
		
		/* generate token */
		var token = "AAAA000000000000000000000000000000000000000000000000000000000000".replace(/0/g,function(){return (~~(Math.random()*16)).toString(16);});
		token = token.toUpperCase();
		
		/* set text */
		$('#'+baseID+'_TXT1').val(token);
	})//-------------------------------------------------
	
	/*
	 * Token clear BUTTON
	 */
	$('button').on('click', function () {
		var thisID = $(this).attr('id');
		var baseID = thisID.replace("_CLS","");
		
		/* no Input and Button */
		if(!thisID.match(/_CLS$/)) {
			//alert('wrong ID: '+thisID); // DEBUG!!!
			return;
		}
		
		/* default token */
		var token = "AAAA000000000000000000000000000000000000000000000000000000000000";
		
		/* set text */
		$('#'+baseID+'_TXT1').val(token);
	})//-------------------------------------------------
	
});






//----------------------------------------------------------------------------//
//  functions                                                                 //
//----------------------------------------------------------------------------//

/*
 * set the Button-Group (ON-OFF-Button)
 * 
 * Example: Button-Group for 'xxxxx'
 *        <div class="btn-group">
 *          <button type="button" id="xxxxx_ON" class="btn btn-success disabled">ON</button>
 *          <button type="button" id="xxxxx_OFF" class="btn btn-danger disabled">OFF</button>
 *        </div>
 *
 * baseID ... string (xxxxx from the example)
 * state .... null: both buttons are gray and enabled
 *            disabled: both buttons are disabled; ON is green; OFF is red
 *            true: ON is enabled, activ and green; OFF is enabled and gray
 *            false: OFF is enabled, activ and red; ON is enabled and gray
 */
function setOnOffButtons(baseID, state) {
		/* reset all */
		$('#'+baseID+'_ON').removeClass("btn-default");
		$('#'+baseID+'_ON').removeClass("btn-success");
		$('#'+baseID+'_ON').removeClass("active");
		$('#'+baseID+'_ON').removeClass("disabled");

		$('#'+baseID+'_OFF').removeClass("btn-default");
		$('#'+baseID+'_OFF').removeClass("btn-danger");
		$('#'+baseID+'_OFF').removeClass("active");
		$('#'+baseID+'_OFF').removeClass("disabled");
		
		/* set class */
		if('null' == state) {
			$('#'+baseID+'_ON').addClass("btn-default");
			$('#'+baseID+'_OFF').addClass("btn-default");
		}else if('disabled' == state) {
			$('#'+baseID+'_ON').addClass("btn-success");
			$('#'+baseID+'_ON').addClass("disabled");
			$('#'+baseID+'_OFF').addClass("btn-danger");
			$('#'+baseID+'_OFF').addClass("disabled");
		}else if(state) {
			$('#'+baseID+'_ON').addClass("btn-success");
			$('#'+baseID+'_ON').addClass("active");
			$('#'+baseID+'_OFF').addClass("btn-default");
		}else {
			$('#'+baseID+'_ON').addClass("btn-default");
			$('#'+baseID+'_OFF').addClass("btn-danger");
			$('#'+baseID+'_OFF').addClass("active");
		}
}//-------------------------------------------------


/*
 * set the Button-Group (LOCAL-GLOBAL-Button)
 * 
 * Example: Button-Group for 'yyyyy'
 *        <div class="btn-group">
 *          <button type="button" id="yyyyy_LOCAL" class="btn btn-info disabled">local</button>
 *          <button type="button" id="yyyyy_GLOBAL" class="btn btn-warning disabled">global</button>
 *        </div>
 *
 * baseID ... string (yyyyy from the example)
 * state .... null: both buttons are gray and enabled
 *            disabled: both buttons are disabled; LOCAL is blue; GLOBAL is orange
 *            true: LOCAL is enabled, activ and blue; GLOBAL is enabled and gray
 *            false: GLOBAL is enabled, activ and orange; LOCAL is enabled and gray
 */
function setLocalGlobalButtons(baseID, state) {
		/* reset all */
		$('#'+baseID+'_LOCAL').removeClass("btn-default");
		$('#'+baseID+'_LOCAL').removeClass("btn-info");
		$('#'+baseID+'_LOCAL').removeClass("active");
		$('#'+baseID+'_LOCAL').removeClass("disabled");

		$('#'+baseID+'_GLOBAL').removeClass("btn-default");
		$('#'+baseID+'_GLOBAL').removeClass("btn-warning");
		$('#'+baseID+'_GLOBAL').removeClass("active");
		$('#'+baseID+'_GLOBAL').removeClass("disabled");
		
		/* set class */
		if('null' == state) {
			$('#'+baseID+'_LOCAL').addClass("btn-default");
			$('#'+baseID+'_GLOBAL').addClass("btn-default");
		}else if('disabled' == state) {
			$('#'+baseID+'_LOCAL').addClass("btn-info");
			$('#'+baseID+'_LOCAL').addClass("disabled");
			$('#'+baseID+'_GLOBAL').addClass("btn-warning");
			$('#'+baseID+'_GLOBAL').addClass("disabled");
		}else if(state) {
			$('#'+baseID+'_LOCAL').addClass("btn-info");
			$('#'+baseID+'_LOCAL').addClass("active");
			$('#'+baseID+'_GLOBAL').addClass("btn-default");
		}else {
			$('#'+baseID+'_LOCAL').addClass("btn-default");
			$('#'+baseID+'_GLOBAL').addClass("btn-warning");
			$('#'+baseID+'_GLOBAL').addClass("active");
		}
}//-------------------------------------------------