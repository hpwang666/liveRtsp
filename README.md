# liveRtsp
使用chrome进行RTSP视频直播，目前支持最新的chrome版本 88.0.4324.182（正式版本） （64 位），视频格式支持H264视频 第一步，打开wsServer文件夹，编译并运行./wsServer 配置nginx代理

location /ws { 
		proxy_pass http://127.0.0.1:9004; 
		#proxy_pass http://172.16.10.4:49240/ws;
		proxy_http_version 1.1; 
		proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";

		#proxy_redirect              off;
		#proxy_set_header            Host $host;
		#proxy_set_header            X-Real-IP $remote_addr;
		#proxy_read_timeout          3600s;
		#proxy_set_header            X-Forwarded-For $proxy_add_x_forwarded_for;
}
第二步，将live.html文件放在nginx的根目录下，然后在浏览器里面打开

第三部，将摄像头的rtsp地址贴到框中，点击set
