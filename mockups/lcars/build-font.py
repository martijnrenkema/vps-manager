import base64, io
from fontTools.ttLib import TTFont
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.pens.transformPen import TransformPen
from fontTools.misc.transform import Transform
from fontTools import subset

CHARS = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
         "abcdefghijklmnopqrstuvwxyz"
         "0123456789"
         " .,:;/\\|-_+*=%()[]{}<>#@!?'\"&$~^`"
         "·°•→×—–▸▪… ")

def condense(src, sx, out_name):
    f = TTFont(src)
    # subset first
    opts = subset.Options()
    opts.layout_features = []
    opts.name_IDs = [1, 2, 4, 6]
    opts.notdef_outline = True
    opts.drop_tables += ['GSUB', 'GPOS', 'kern', 'DSIG']
    subsetter = subset.Subsetter(options=opts)
    subsetter.populate(text=CHARS)
    subsetter.subset(f)

    glyphSet = f.getGlyphSet()
    t = Transform(sx, 0, 0, 1, 0, 0)
    new = {}
    for name in f.getGlyphOrder():
        pen = TTGlyphPen(glyphSet)
        glyphSet[name].draw(TransformPen(pen, t))
        new[name] = pen.glyph()
    glyf = f['glyf']
    hmtx = f['hmtx']
    for name, g in new.items():
        glyf[name] = g
        aw, lsb = hmtx[name]
        hmtx[name] = (max(0, round(aw * sx)), round(lsb * sx))

    f.flavor = 'woff2'
    buf = io.BytesIO()
    f.save(buf)
    data = buf.getvalue()
    print(out_name, len(data), 'bytes ->', len(base64.b64encode(data)), 'b64')
    return base64.b64encode(data).decode('ascii')

L = '/usr/share/fonts/truetype/liberation/'
bold = condense(L + 'LiberationSans-Bold.ttf', 0.545, 'lcars-bold')
reg  = condense(L + 'LiberationSans-Regular.ttf', 0.58, 'lcars-reg')

with open('fonts.css', 'w') as fh:
    fh.write("@font-face{font-family:'LcarsCond';font-style:normal;font-weight:700;font-display:block;"
             "src:url(data:font/woff2;base64,%s) format('woff2')}\n" % bold)
    fh.write("@font-face{font-family:'LcarsCond';font-style:normal;font-weight:400;font-display:block;"
             "src:url(data:font/woff2;base64,%s) format('woff2')}\n" % reg)
print('css bytes:', len(open('fonts.css').read()))
