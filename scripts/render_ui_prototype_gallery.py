#!/usr/bin/env python3
"""Build the saved v1 prototype gallery and manifests; no image generation/network."""
from pathlib import Path
from html import escape
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'docs/public/prototypes/v1'
PROMPTS = ROOT / 'docs/design/ui/prompts.json'
LABELS = {
 'desktop-overview': ('D01', '桌面 · 总览', 'Desktop overview', '连接、模式、并行场景、业务流量与媒体检测摘要'),
 'desktop-nodes': ('D02', '桌面 · 节点与订阅', 'Nodes and subscriptions', '来源、分组选择、更新差异与能力状态'),
 'desktop-rules': ('D03', '桌面 · 规则与区域', 'Rules and regions', '规则/全局/直连、区域预设、三桌面进程规则与切换影响'),
 'desktop-network': ('D04', '桌面 · 网络与 DNS', 'Network and DNS', '接管、fake-ip/redir-host、DNS出站、引导解析、按需嗅探'),
 'desktop-diagnostics': ('D05', '桌面 · 连接诊断', 'Connection diagnostics', '实际轨迹、计划/实际出口、回退、未知原因与只读AI'),
 'desktop-developer': ('D06', '桌面 · 开发者代理', 'Developer proxy', 'Git/SSH/GitHub路由、当前终端、配置预览与连通性'),
 'ios-home': ('I01', 'iOS · 首页', 'iOS home', '原生列表、模式、场景、业务流量与常用工具'),
 'ios-network': ('I02', 'iOS · 网络设置', 'iOS network settings', 'DNS应答、查询出站、例外、嗅探与应用预览'),
 'android-home': ('A01', 'Android · 首页', 'Android home', 'Material风格、VPN状态、模式与并行场景'),
 'android-network': ('A02', 'Android · 网络设置', 'Android network settings', '独立DNS/区域控制与变更预览'),
}

def main():
    inputs = json.loads(PROMPTS.read_text(encoding='utf-8'))
    records = []
    for item in inputs['images']:
        name = item['name']
        path = ASSETS / f'{name}.png'
        data = path.read_bytes()
        assert data[:8] == b'\x89PNG\r\n\x1a\n', path
        width, height = struct.unpack('>II', data[16:24])
        ident, zh, en, features = LABELS[name]
        records.append(dict(id=ident, name=name, title_zh=zh, title_en=en,
                            features=features, file=path.name, width=width, height=height,
                            bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                            revision=item.get('revision', 1)))
    assert len(records) == 10
    manifest = {'design_version': 'v1', 'status': 'visual prototypes, fictional data, not implemented clients',
                'created': '2026-11-15', 'generation': 'built-in image_gen', 'images': records}
    (ASSETS/'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n')
    cards = []
    for item in records:
        cards.append(f'''<article id="{item['id']}" class="{'mobile' if item['height']>item['width'] else 'desktop'}">
<h2>{item['id']} · {escape(item['title_zh'])}</h2><p>{escape(item['features'])}</p>
<a href="{item['file']}" target="_blank" rel="noopener"><img loading="lazy" src="{item['file']}" width="{item['width']}" height="{item['height']}" alt="{escape(item['title_zh'])} 原型示例" /></a>
<footer><a href="{item['file']}" download>下载 PNG</a><span>{item['width']} × {item['height']}</span></footer></article>''')
    nav=' '.join(f'<a href="#{x["id"]}">{x["id"]}</a>' for x in records)
    html='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rillane v1 原型图库</title><style>
:root{color-scheme:light;font-family:system-ui,"Noto Sans CJK SC",sans-serif;color:#19313c;background:#f5f7f8}body{margin:0 auto;max-width:1440px;padding:32px 24px}h1{font-size:36px;margin-bottom:12px}p{line-height:1.7;color:#526674}nav{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0}a{color:#007f78}nav a{padding:8px 14px;background:white;border:1px solid #d8e3e6;border-radius:8px;text-decoration:none}main{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px}article{background:white;border:1px solid #d8e3e6;border-radius:12px;padding:20px;scroll-margin-top:20px}article.desktop{grid-column:1/-1}h2{margin:0;font-size:22px}img{display:block;width:100%;height:auto;border-radius:8px}article.mobile img{max-width:440px;margin:auto}footer{display:flex;justify-content:space-between;margin-top:16px;font-size:14px}aside{padding:16px 20px;border-left:4px solid #007f78;background:#e9f4f2;line-height:1.8}small{color:#60777e}@media(max-width:750px){body{padding:20px 12px}main{grid-template-columns:1fr}h1{font-size:28px}article{padding:12px}}
</style><header><small>RILLANE · DESIGN V1</small><h1>连接看得见，策略讲得清</h1><p>桌面 6 页 / iOS 2 页 / Android 2 页。点击图片查看原图，可直接离线打开本文件。</p></header>
<aside>这是静态视觉原型，所有连接、流量与检测结果均为示例。图片上的按钮不可操作，不能证明功能已经实现。规则/全局/直连、DNS应答模式、DNS查询出站属于不同控制层。生成图中的Logo和细节图标尚待组件设计统一。</aside>
<nav>'''+nav+'</nav><main>'+''.join(cards)+'''</main><p>界面参考：Clash Verge 官方预览、Shadowrocket App Store 产品资料。iMac仅确认到进程，未获取实时窗口截图。后续以UI交互规格和内核能力回执为准。</p><p><a href="manifest.json">文件清单与SHA-256</a></p></html>'''
    (ASSETS/'index.html').write_text(html, encoding='utf-8')
    for lang in ('', 'zh/'):
        zh = bool(lang)
        dst=ROOT/f'docs/{lang}design/ui/README.md'; dst.parent.mkdir(parents=True,exist_ok=True)
        title='# v1 UI 原型交付' if zh else '# v1 UI prototype delivery'
        intro=('已保存 **10 张独立原型图：桌面 6 张、iOS 2 张、Android 2 张**。当前为视觉与交互提案；全部数值为示例。' if zh else '**10 standalone prototypes saved: six desktop, two iOS and two Android.** Visual/interaction proposals only; all values are fictional.')
        body=title+'\n\n'+intro+'\n\n'
        body+=('[离线/浏览器图库](/prototypes/v1/index.html) · [交互规格](../ui-prototype-v1.md) · [生成提示词与修改记录](https://github.com/cuihairu/rillane/blob/main/docs/design/ui/prompts.json)\n\n' if zh else '[Offline/browser gallery](/prototypes/v1/index.html) · [Interaction specification](../ui-prototype-v1.md) · [Prompts/revisions](https://github.com/cuihairu/rillane/blob/main/docs/design/ui/prompts.json)\n\n')
        body+=('保存目录：`docs/public/prototypes/v1/`。`index.html` 可直接用浏览器打开；`manifest.json` 包含尺寸、SHA-256 和修订号。使用内置 image_gen 生成，随后复制到仓库；生成提示词与四张图的修改提示词已落盘。\n\n' if zh else 'Files live in `docs/public/prototypes/v1/`. Open index.html directly; manifest.json records dimensions, SHA-256 and revisions. Generated with built-in image_gen and copied into the repository, with prompts and four revision prompts preserved.\n\n')
        body+=('图片表达布局与主题，Logo/图标不是已冻结品牌。产品实现以交互规格为准：状态来自内核/宿主确认，业务流量不重复累计，流媒体不承诺持续解锁，移动不承诺任意PID归因。iMac已确认Clash Verge进程，但未获实时窗口截图；参考官方预览与App Store资料。\n\n' if zh else 'Images define layout/theme; logos/icons are not a frozen brand system. Implementation follows the interaction specification, actual capability receipts, single-count business totals, measured streaming results and mobile identity limits. iMac processes were confirmed, but no live window screenshot was obtained; references use official previews/App Store information.\n\n')
        for item in records:
            label=item['title_zh'] if zh else item['title_en']
            body+=f'## {item["id"]} · {label}\n\n'
            if zh: body+=item['features']+'。\n\n'
            body+=f'![{label} 原型示例](/prototypes/v1/{item["file"]})\n\n'
        dst.write_text(body.rstrip()+'\n',encoding='utf-8')
    print('Rendered 10-image gallery, bilingual delivery pages and SHA-256 manifest')

if __name__ == '__main__':
    main()
