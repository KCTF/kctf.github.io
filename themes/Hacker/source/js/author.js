
function getAuthor(user){
    name=user.name;
    if(user.avatar) avatar=user.avatar;
    else avatar="https://img.5am3.com/kn0ck-red.png";

    if(user.solgn) solgn=user.solgn;
    else solgn="大佬表示，他什么都不想说";
    

    var text = '<div class="friend-card">';
    text += '<div class="friend-card-layer">';
    text += '    <div class="friend-card-meta">';
    text += '    <p>'+solgn+'.</p>';
    text += '    </div>';
    text += '    <img class="friend-card-avatar" src="'+avatar+'">';
    text += '</div>';
    text += '<div class="friend-card-content">';
    text += '    <div class="friend-card-content-title">'+name+'</div>';


    // id-card-o
    if(user.retire) {
        text += '    <i class="fa fa-id-card-o fa-lg testShowInfo" data-title="退役"></i>';
    }else{
        text += '    <i class="fa fa-id-card fa-lg testShowInfo" data-title="在役"></i>';
    }
    
    // blog
    if(user.blog) {
        blogUrl=user.blog;
    
        text += '    <a href="'+blogUrl+'" target="_blank" class="friend-card-content-site">';
        text += '       <i class="fa fa-home fa-lg testShowInfo" data-title="博客"></i>';
        text += '    </a>';
    }
    

    // github
    if(user.github) {
        github=user.github;
    
        text += '    <a href="'+github+'" target="_blank" class="friend-card-content-site">';
        text += '       <i class="fa fa-github fa-lg testShowInfo" data-title="GitHub"></i>';
        text += '    </a>';
    }


    // weibo

    if(user.weibo) {
        weibo=user.weibo;
        text += '    <a href="'+weibo+'" target="_blank" class="friend-card-content-site">';
        text += '       <i class="fa fa-weibo fa-lg testShowInfo" data-title="微博"></i>';
        text += '    </a>';
    }

    // mail
    if(user.mail) {
        mail=user.mail;
        text += '    <a href="mailto:'+mail+'" target="_blank" class="friend-card-content-site">';
        text += '       <i class="fa fa-envelope fa-lg testShowInfo" data-title="邮箱"></i>';
        text += '    </a>';
    }


    // telegram


    // text += '    <a href="'+blogUrl+'" target="_blank" class="friend-card-content-site">';
    // text += '    '+blogUrl.replace(/http:\/\/|https:\/\//, "").replace(/\/$/,"")+'';
    // text += '    </a>';
    text += '</div>';
    text += '</div>';

    return text;
}

function showUsers(UserList){

    text = "";
    retireText = "";

    retireText += "<br>";
    retireText += "<br>";
    retireText += "<h3>一路走来，感谢那些曾带我们飞的大佬。</h3>";
    retireText += "<br>";
    for(var i = 0;i<UserList.length;i++){
        if(UserList[i].retire){
            retireText += getAuthor(UserList[i]);
        }else{
            text += getAuthor(UserList[i]);
        }
        
    }
    showText = text + retireText;
    showText +='<style>.article-top-meta{display: none;}</style>';
    showText +='<link rel="stylesheet" href="/font-awesome/css/font-awesome.min.css">';

    document.getElementsByClassName("article-content")[0].innerHTML = showText;
}

(function() {
    var ajax = new XMLHttpRequest();
    ajax.open('get','/api/author');
    ajax.send();
    ajax.onreadystatechange = function () {
        if (ajax.readyState==4 &&ajax.status==200) {
            UserList = JSON.parse(ajax.responseText)
            showUsers(UserList['data'])
    　　}
    }
})();


