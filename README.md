# IP 查询服务

## 项目简介

这是一个轻量级的 IP 查询服务，提供以下功能：
- 获取客户端公网 IP 地址
- 查询 IP 地理位置信息
- 显示网络运营商信息
- 支持网页和命令行两种访问方式

## 功能特性

✅ **多方式获取 IP**  
- 自动识别 X-Forwarded-For 头
- 支持 IPv4/IPv6 地址
- 多层级备用 IP 获取方案

✅ **地理位置查询**  
- 基于百度开放 API
- 自动解析省份/城市
- 显示网络运营商信息

✅ **多种访问方式**  
- 网页端：完整信息展示
- 命令行：直接返回纯文本 IP

✅ **安全防护**  
- 自动屏蔽常见爬虫
- Referer 安全检查
- 可疑请求自动拦截

## 快速开始

### 安装依赖
```bash
npm install express node-fetch
```

### 启动服务
```bash
node index.js
```
```bash
服务默认运行在 http://localhost:3000

环境变量配置
| 变量名 | 默认值 | 说明 | 
|-------|-------|------|
| SERVER_PORT | 3000 | 服务监听端口 |
| PAGE_TITLE | "IP查询" | 网页标题 |
| COPYRIGHT | "IP查询服务" | 版权信息 |
```
#### 网页访问
使用示例
网页访问
直接访问服务地址查看完整信息：

![image-20250514172330900](https://github.com/pospos369/ipcheck/blob/main/images/image-20250514172330900.png)

#### 命令行访问
```bash
curl -L your-server-address
```

### 部署建议
#### 生产环境建议：

使用 Nginx 反向代理
配置 HTTPS 加密
设置合理的请求频率限制

#### Docker 部署：
```bash
docker build -t ip-checker .
docker run -p 3000:3000 -d ip-checker
```
### 注意事项：
```bash
地理位置服务依赖百度 API，精度有限
技术实现
采用 Express 框架
使用 ES Module 规范
内存缓存优化性能
响应式网页设计
注意事项
地理位置服务依赖百度 API，精度有限
频繁请求可能会触发防护机制
建议自行替换地理位置查询接口
许可证
MIT License © 2023
```