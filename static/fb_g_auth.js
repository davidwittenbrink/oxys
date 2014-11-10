$( document ).ready(function() {
    //action=social_login
});



var AuthStates = {google: null, facebook: null}

window.fbAsyncInit = function() {
    // init the FB JS SDK
    FB.init({
        appId      : 'APPID',              	// App ID from the app dashboard
        channelUrl : document.URL + '/channel.html',// Channel file for x-domain comms
        status     : true,                                  	// Check Facebook Login status
        cookie 	  : true, 												// enable cookies to allow the server to access the session	      
        xfbml      : true                                  	// Look for social plugins on the page
    });
    
    FB.Event.subscribe('auth.authResponseChange', function(response) {
        // Here we specify what we do with the response anytime this event occurs. 
        if (response.status === 'connected') {
            AuthStates.facebook = response.status; 
            chooseAuthProvider();
        } 
    });
};

var trigger_Loading = function() {
    if(! $("#loading").html()) {
        html = '<div id="loading" style="text-align: center;  position: fixed; height: 70px; width: 300px; background-color: white;z-index:4; top: 50%; left: 50%; margin-left: -150px; margin-top: -35px;"><div style="height: 23px;margin-top: 23.5px;" >Loading...</div></div>'
        $('body').prepend(html);
        $('#content-wrapper').toggleClass('blur');
    }
    else {
        $("#loading").remove();
        $('#content-wrapper').removeClass('blur');
    }
}

function GetURLParameter(sParam)
{
    var sPageURL = window.location.search.substring(1);
    var sURLVariables = sPageURL.split('&');
    for (var i = 0; i < sURLVariables.length; i++) 
    {
        var sParameterName = sURLVariables[i].split('=');
        if (sParameterName[0] == sParam) 
        {
            return sParameterName[1];
        }
    }
}
// Load the SDK asynchronously
(function(d, s, id){
    var js, fjs = d.getElementsByTagName(s)[0];
    if (d.getElementById(id)) {return;}
    js = d.createElement(s); js.id = id;
    js.src = "//connect.facebook.net/en_US/all.js";
    fjs.parentNode.insertBefore(js, fjs);
}(document, 'script', 'facebook-jssdk'));

function ajaxLogin(url){
    trigger_Loading();
    var hostURL= document.URL;
    if(hostURL.charAt(hostURL.length - 1) == "/") {hostURL = hostURL.substring(0, hostURL.length - 1)}
    $.when(
    $.ajax({
        type: "GET",
        url: hostURL + url,
        dataType: "html",
        timeout: 180000, // in milliseconds
        success: function(data, textStatus, XMLHttpRequest){
            trigger_Loading();
            
            //window.location = "/?action=social_login";
        },
        error: function(request, status, err) {
            trigger_Loading();
            console.log("" + status + " " + err);
            //alert("There was an error. Sorry!");
        }
    })).then(function(){window.location="/"});
}

function checkIfSessionCookieExists(){
    cookies = document.cookie.split(";");
    for(i=0; i<cookies.length; i++){
        if(cookies[i].substring(0, 7) === "session" && cookies[i].length >= 10){
            return true;
        }
    }
    return false;	   
}
//GOOGLE LOGIN JS
// Asynchronously load the client library
(function() {
    var po = document.createElement('script'); po.type = 'text/javascript'; po.async = true;
    po.src = 'https://apis.google.com/js/client:plusone.js?onload=render';
    var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(po, s);
})();

function signinCallback(authResult) {
    if (authResult['access_token']) {
        AuthStates.google = authResult;
        chooseAuthProvider();
    } 
}

function setGPlusCookie(access_token) {
    if (access_token) {
        var now = new Date();
        var time = now.getTime();
        time += 3600 * 1000;
        now.setTime(time);
        document.cookie = 
            'google_plus_sign_in=' + access_token + 
            '; expires=' + now.toGMTString() + 
            '; path=/;';  	
    }
    else {console.log("cookie not set");}
}

function chooseAuthProvider() {
    if(AuthStates.google) {
        //trigger_Loading();
        setGPlusCookie(AuthStates.google['access_token']);
        ajaxLogin("/gplogin");           
    }
    else if (AuthStates.facebook === 'connected') {
        //trigger_Loading();
        ajaxLogin("/fblogin");
    }
}

