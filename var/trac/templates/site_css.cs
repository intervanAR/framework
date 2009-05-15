<?cs
##################################################################
# Site CSS - Place custom CSS, including overriding styles here.

?>
.wikipage h2 {border-bottom: 1px solid gray;}

/* trac php syntax highlighting */
.code-block {
    line-height: 1em;
    font-family: Courier, monotype;
    font-size: 12px;
    }
.h_question { color: #0000BB; } /* highlight.default */
.hphp_commentline { color: #FF8000; } /* highlight.comment */
.hphp_operator { color: #007700; } /* highlight.keyword */
.hphp_word { color: #007700; } /* highlight.keyword */
.hphp_default {}
.hphp_variable { color: #0000BB; } /* highlight.default */
.hphp_hstring { color: #DD0000; } /* highlight.string */
.hphp_simplestring { color: #DD0000; } /* highlight.string */
.h_tagunknown {}
.h_default {}

.code-keyword { color: #007700; font-weight: normal; }
.code-lang { color: #0000BB; font-weight: normal; }
.code-comment { color: #FF8000; font-weight: normal;}
.code-string { color: #DD0000; font-weight: normal;}

pre { padding:0; margin: 0}

.tablas-screenshots td:first-child { background-color: #D5CECD; width: 30%}
.tablas-screenshots table { width: 90%; border: 1px solid gray; }
.tablas-screenshots td { }
.tablas-screenshots table.wiki td { border: 1px solid gray; }

#tkt-changes-hdr {
    clear: both;
    padding-top: 30px;
}
.wiki-toc {
    clear: right;
    min-width: 160px;
    background-color:#F7F7F7;    
    border: 1px solid #D7D7D7;
}
.wiki-toc .active {
    background-color: #890C71;
    padding: 1px;
}
.wiki-toc .active a {
    color:white; 
}
.wiki-toc .active a:hover {
    background-color:  #890C71;
}
.indice-general {
/*    background-color: #FFFFDD;*/
}
.wikipage h1 {
    padding-top: 5px;
}
.wikipage h2 {
 padding: 2px;
}
h1 {
    font-size: 28px;
}
.wikipage h2 {
    background-color: #890C71;
    color: white;
    padding-left: 10px;
    margin-top: 30px;
    font-size: 100%;
    border: 1px solid gray;
}
.wikipage h3 {
    font-size:100%;
}
.wikipage {
padding-right:10px;
}
li {
    margin-bottom:6px;
}
li * {
    margin-bottom:3px;
}
/*a {
 color: #890C71;
}*/
@media print {
 .wiki-toc { display: none }
}
#tkt-changes-hdr, .tkt-chg-list { 
    font-size:80%;
    text-align:right;
}

/** Cambios globales **/
#ctxtnav {
 display:none;
}
#mainnav {
 border: none;
 background: white;
 margin: 0;
 padding-top: 10px;
 padding-bottom: 35px;
border-bottom:1px solid #CCCCCC;

}
#mainnav li {
 border: 1px solid lightGray;
}
#header {
 display:none;
}
body {
    margin: 0;
    padding: 0;
      background-color:#F3F3F3;	    
}
#content {
clear: both;

}
#banner {
    background-color: white;
    padding-right:10px;
    padding-top:10px;
}

#mainnav .active :link, #mainnav .active :visited {
background:#890B72;
border-right:1px solid #000000;
border-top:medium none;
color:#EEEEEE;
font-weight:bold;
}
#mainnav :link, #mainnav :visited {
 border: none;
 background: transparent;
}
:link, :visited {
/* color: #1020EB;*/
/* color: #0C1BBC; */
 color: #67065D ;

}
#main {
 padding-left: 10px;
}
#footer {
 background-color: white;
 border-bottom: 1px solid;
}
