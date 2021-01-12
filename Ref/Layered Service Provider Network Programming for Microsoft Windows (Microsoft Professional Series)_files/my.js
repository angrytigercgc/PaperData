
$(document).ready(function(){
		$(document).on('click','[data-path]',function(){location.href=$(this).attr('data-path');});
		$(document).on('mouseover','[data-path-blank]',function(){$(this).attr('href', 'http://www.amazon.com/s/?url=search-alias=stripbooks&field-keywords='+$(this).attr('data-path-blank')+'&tag=technicalibra-20&link_code=wql&camp=212361&creative=380601&_encoding=UTF-8');});
		
		$(document).on('click','[data-path-blank]',function(){yaCounter22278580.reachGoal('get_out');});
		$(document).on('click','[data-p]',function(){yaCounter22278580.reachGoal('get_out_adb');});
		$(document).on('mouseout','[data-path-blank]',function(){$(this).attr('href', 'javascript:;');});
		
		$('[data-action="top"]').click(function() {
		  $("html, body").animate({ scrollTop: 0 }, "slow");
		  return false;
		});
			//var h1=parseInt($('.lc').height());
			//var h2=parseInt($('.rc').height());
			//$(".og").readMore({previewHeight: h1});
});
$(document).on('click','.cookies_button',function(){
	$.cookie('cookie_accepted', true, { path: '/' });
	$('.cookie_notify').hide();
});
if($.cookie('cookie_accepted')!="true"){
	$('.cookie_notify').show();
}
jQuery(function (f) {
    f(window).scroll(function () {
		if ($(window).width() >= '1000'){
			f('#secondary_bar')[(f(this).scrollTop() > 555 ? "add" : "remove") + "Class"]("bar_fixed");
		}
		f('#top')[(f(this).scrollTop() > 555 ? "add" : "remove") + "Class"]("top_fixed");

    });
	 f(window).resize(function() {
		 if ($(window).width() >= '1000'){
			f('#secondary_bar')["removeClass"]("bar_fixed");
		}
	 });
});


