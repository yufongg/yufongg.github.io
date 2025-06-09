---
title: Markdown Parser
author: yufong
categories: Web
date: 2024-04-21
date_time: 2024-04-21 10:47
tags: 
- web/xss
details: XSS in Markdown fenced code block	
difficulty: 2
solved: yes
solution: "https://github.com/NUSGreyhats/greyctf24-challs-public/tree/main/quals/web/markdown-parser"
img_path: /Writeups/CTF/GreyCTF%202024/Web/Markdown%20Parser/attachments/
image:
  src: ../../Beautiful%20Styles/attachments/Beautiful%20Styles-20240510000105525.png
  width: 1000   # in pixels
  height: 400   # in pixels
---



# Source Code Analysis
- `markdown.js`
	```
	function parseMarkdown(markdownText) {
	    const lines = markdownText.split('\n');
	    let htmlOutput = "";
	    let inCodeBlock = false;
	
	    lines.forEach(line => {
	        if (inCodeBlock) {
	            if (line.startsWith('```')) {
	                inCodeBlock = false;
	                htmlOutput += '</code></pre>';
	            } else {
	                htmlOutput += escapeHtml(line) + '\n';
	            }
	        } else {
	            if (line.startsWith('```')) {
	                language = line.substring(3).trim();
	                inCodeBlock = true;
	                // add class to code block for syntax highlighting
	                htmlOutput += '<pre><code class="language-' + language + '">';
	            } else {
	                line = escapeHtml(line);
	                line = line.replace(/`(.*?)`/g, '<code>$1</code>');
	```
	>Vulnerability Details:
	>- It is possible to inject XSS code on the same line as the triple backtick
	>- In markdown the triple backticks, is used to start a code block. After the 3 backticks, it is used to declare the language that resides in the code block. Since no input sanitization is done, we can inject xss there
	{: .prompt-info}
	
# Solution

<video muted autoplay controls style="width: 740px; height: 460px;">
	<source src="{{site.img_cdn}}{{page.img_path}}fIpqfFcrFW.mp4" type="video/mp4">
</video>
