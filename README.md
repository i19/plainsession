## plainsession

===

HTTP Session 的加密封装，通过 cookie 实现

```
session, err := plainsession.New(Config.SessionValidDays * 86400, Config.SessionSecret)

s.Set("country", "cn")

s.Del("country")

s.Flush()

value, exist := s.Get("country)

s.GetValues()

encryption := s.GetEncryption()

err := s.Descrpt(encryption)

```


