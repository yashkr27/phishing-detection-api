import sys
sys.path.insert(0, '.')
from app.predict import predict_url

phishing_urls = [
    'https://zjfq4lnfbs7pncr5.tor2web.org/',
    'https://docs.google.com/spreadsheets/viewform?formkey=dE5rVEdSV2pBdkpSRy11V3o2eDdwbnc6',
    'https://jhomitevd2abj3fk.onion.to/',
    'https://mphtadhci5mrdlju.tor2web.org/',
    'https://tinyurl.com/c5br4qc',
    'http://lingshc.com/old_aol.1.3/?Login=&Lis=10&LigertID=1993745&us=1',
    'https://sunix-technology.com/admin/sdy.png',
    'http://105.184.194.116:48473/bin.sh',
    'http://zippycanyonez.pro/00101010101001/juan.x8',
    'http://asladconcentration.com/paplkuk1/webscrcmd=_home-customer&nav=1/',
    'http://www.regaranch.info/grafika/file/2012/atualizacao/www.itau.com.br/',
    'http://optimistic-pessimism.com/aoluserupdatealert.info.htm',
    'https://mcb0187.gamer.gd/img_070947.png',
    'http://www.wallhome.com/M5.php',
]

legit_urls = [
    'https://www.google.com/',
    'https://www.youtube.com/',
    'https://web.whatsapp.com/',
    'https://www.amazon.com/',
    'https://github.com/',
]

print("=" * 90)
print("PHISHING URLs (should all be caught)")
print("=" * 90)
hits = 0
misses = 0
for u in phishing_urls:
    try:
        r = predict_url(u)
        label = r['label']
        conf = r['confidence']
        ml = r.get('ml_phishing_prob', '?')
        hs = r.get('heuristic_score', '?')
        triggers = r.get('heuristic_triggers', [])
        trigger_names = [t[0] for t in triggers] if triggers else []
        if label == 'phishing':
            hits += 1
            tag = ' OK  '
        else:
            misses += 1
            tag = 'MISS '
        print(f"[{tag}] {label:>10} {conf:.1%}  ml={ml} h={hs} {trigger_names}")
        print(f"        {u[:80]}")
    except Exception as e:
        misses += 1
        print(f"[ERR  ] {e}")
        print(f"        {u[:80]}")

print(f"\n--- Phishing: {hits}/{hits+misses} caught, {misses} missed ---\n")

print("=" * 90)
print("LEGITIMATE URLs (should NOT be flagged)")
print("=" * 90)
fp = 0
for u in legit_urls:
    try:
        r = predict_url(u)
        label = r['label']
        conf = r['confidence']
        ml = r.get('ml_phishing_prob', '?')
        hs = r.get('heuristic_score', '?')
        triggers = r.get('heuristic_triggers', [])
        trigger_names = [t[0] for t in triggers] if triggers else []
        if label == 'phishing':
            fp += 1
            tag = 'FP!!!'
        else:
            tag = ' OK  '
        print(f"[{tag}] {label:>10} {conf:.1%}  ml={ml} h={hs} {trigger_names}")
        print(f"        {u}")
    except Exception as e:
        print(f"[ERR  ] {e}  {u}")

print(f"\n--- Legitimate: {fp} false positives ---")
