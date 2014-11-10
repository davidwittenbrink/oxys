(function(d, s, id) {
    var js, fjs = d.getElementsByTagName(s)[0];
    if (d.getElementById(id)) return;
    js = d.createElement(s); js.id = id;
    js.src = "//connect.facebook.net/de_DE/all.js#xfbml=1&appId=appID";
    fjs.parentNode.insertBefore(js, fjs);
}(document, 'script', 'facebook-jssdk'));


function logOut() {
    FB.getLoginStatus(function(response) {
        var URL = window.location.protocol + "//" + window.location.host
        if (response.status === 'connected') {
            FB.logout(function(response) {
                if (response.status !== 'connected') {
                    window.location = "https://www.google.com/accounts/Logout?continue=https://appengine.google.com/_ah/logout?continue=" + URL + '/logout';
                } 
            });	  				
        } else window.location = "https://www.google.com/accounts/Logout?continue=https://appengine.google.com/_ah/logout?continue=" + URL + '/logout';
    })
}
var trigger_Loading = function() {
    if(! $("#loading").html()) {
        html = '<div id="loading" style="text-align: center;  position: fixed; height: 70px; width: 300px; background-color: white;z-index:4; top: 50%; left: 50%; margin-left: -150px; margin-top: -35px;"><div style="height: 23px;margin-top: 23.5px;" >Loading...</div></div>'
        $('body').prepend(html);
        $('#ultraContainer').toggleClass('blur');
        //$('#header').toggleClass('blur');
    }
    else {
        $("#loading").remove();
        $('#ultraContainer').removeClass('blur');
        //$('#header').removeClass('blur');
    }
}

var showMenu = function() {
    $('body').toggleClass("active-nav");
    $('.sidebar-button').removeClass("active-button");				
    $('.menu-button').toggleClass("active-button");	
}

$( document ).ready(function() {
    // Toggle for nav menu
    $('.menu-button').click(function(e) {
        e.preventDefault();
        showMenu();							
    });	
    // Handler for .ready() called.
    setWidthAsItemHeight("nav li");
    $(".menu-log-out").click(function(event){
        event.preventDefault();
        logOut();
    });
});

// add/remove classes everytime the window resize event fires
jQuery(window).resize(function(){
    //setWidthAsItemHeight(".calendar-table")
    var off_canvas_nav_display = $('.off-canvas-navigation').css('display');
    var menu_button_display = $('.menu-button').css('display');
    setWidthAsItemHeight("nav li");
    if (off_canvas_nav_display === 'block') {			
        $("body").removeClass("three-column").addClass("small-screen");				
    } 
    if (off_canvas_nav_display === 'none') {
        $("body").removeClass("active-sidebar active-nav small-screen")
        .addClass("three-column");			
    }	
    
});

var setWidthAsItemHeight = function(s) {
    $( s ).height($( s ).width());
}


function drawCalendar(month, year) {
    var days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    var monthNames = ['January','February','March','April',
                      'May','June','July','August','September','October',
                      'November','December'];
    var daysInMonth = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    var currentDate = new Date();
    month = (isNaN(month) || month === null) ? currentDate.getMonth() : month;
    year  = (isNaN(year) || year === null) ? currentDate.getFullYear() : year;
    var html = '';
    
    var todayCSSclass = '.calendar-day-' + currentDate.getDate() + '-' + (currentDate.getMonth() + 1) + '-' + currentDate.getFullYear();
    $('head').append('<style type="text/css">' + todayCSSclass + '{border: 1px solid #e99322;}</style>');
    

    
    var firstDay = new Date(year, month, 1);
    var monthStartingDay = firstDay.getDay();
    var monthLength = daysInMonth[month];
    
    //Figure out if it's a leap year....
    if (month == 1) { // February only!
        if ((year % 4 === 0 && year % 100 !== 0) || year % 400 === 0){
            monthLength = 29;
        }
    }
    //----//
    var monthName = monthNames[month];
    html = '<table class="calendar-table">';
    html += '<tr><th colspan="7">';
    html += '<div class="arrow month-left">&lt;</div>'
    html +=  monthName + "&nbsp;" + year;
    html += '<div class="arrow month-right">&gt;</div>'
    html += '</th></tr>';
    html += '<tr class="calendar-header">';
    for (var i = 0; i <= 6; i++ ){
        html += '<td class="calendar-header-day">';
        html += days[i];
        html += '</td>';
    }
    html += '</tr>';
    
    var day=1;
    
    for(i=0; i<= 8; i++) {
        html += "<tr>"; //For each Week
        for(weekday=0; weekday<7 && day <= monthLength; weekday++) {
            //For each Day
            
            var hasStarted = false;
            
            if((day==1 && monthStartingDay == weekday) || day > 1) {
                //The first day of the month does not have
                //to be a sunday.
                html += '<td role="button" class="calendar-day calendar-day-' + day + '-' + (month + 1) + '-' + year + '">';
                html += day;
                day++;
                html += "</td>";
            }
            else {
                html+= "<td></td>";  
            }
            
        }
        html += "</tr>";      
    }
    html += '</table>';
    return html;
}

var TODAY = new Date();
var MONTH = TODAY.getMonth();
var YEAR = TODAY.getFullYear();

function incrementMonth() {
    if(MONTH == 11) {
        YEAR++;
        MONTH = 0;
    }
    else {
        MONTH++;
    }
    
}

function decrementMonth() {
    if(MONTH === 0) {
        YEAR--;
        MONTH = 11;
    }
    else {
        MONTH--;
    } 
}

function triggerLoading(){
    $( "#ultraContainer" ).toggleClass( "blur" );
    $( "#header" ).toggleClass( "blur" );
}

var showProfile = function () {
    triggerLoading();
    $("#profile-information").toggle();
}
