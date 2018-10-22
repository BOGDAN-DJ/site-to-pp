$('.nav-toggle').on('click', function(){
    $('#menu').toggleClass('active');
});

$(window).scroll(function () {
    var ratio = $(document).scrollTop () / (($(document).height () - $(window).height ()) / 100);
    $("#progress").width (ratio + "%");
});