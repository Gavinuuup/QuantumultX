/*************************Nobyda

[rewrite_local]
# 获取京东Cookie. 
^https:\/\/(api\.m|me-api)\.jd\.com\/(client\.action\?functionId=signBean|user_new\/info\/GetJDUserInfoUnion\?) url script-request-header https://raw.githubusercontent.com/NobyDa/Script/master/JD-DailyBonus/JD_DailyBonus.js

[mitm]
hostname = ms.jr.jd.com, me-api.jd.com, api.m.jd.com