from __future__ import annotations


class DnsError(Exception):
    def __init__(self, message: str, detail: str = ""):
        self.message = friendly_error(message)
        self.detail = detail or message
        super().__init__(self.message)


def friendly_error(message: str) -> str:
    text = str(message)
    rules = (
        ("AccessPolicyDenied", "访问被密钥策略拒绝，通常是 IP 白名单。请给这个平台或全局配置代理，走允许的出口。"),
        ("InvalidAccessKeyId.NotFound", "AccessKey ID 不存在。"),
        ("InvalidAccessKeySecret", "AccessKey Secret 不正确。"),
        ("SignatureDoesNotMatch", "签名不匹配，请检查密钥是否填反或带了空格。"),
        ("AuthFailure.SecretIdNotFound", "SecretId 不存在。"),
        ("AuthFailure.SignatureFailure", "腾讯云签名失败，请检查 SecretKey。"),
        ("UnauthorizedOperation", "这个密钥没有 DNS 权限。"),
        ("InvalidAccessKeyId", "AccessKey 无效。"),
        ("AuthFailure", "腾讯云认证失败，请检查 SecretId / SecretKey。"),
    )
    for key, label in rules:
        if key in text:
            return label
    lowered = text.lower()
    if "proxy" in lowered or "socks" in lowered:
        return "代理连接失败，请检查代理地址、账号和端口。"
    return text
