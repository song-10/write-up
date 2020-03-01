# coding = 'utf-8'
from PIL import Image    # 引入Image库对图片进行操作


# ascii列表，将其与图片像素对应
ascii_char = list("$@B%8&WM#*oahkbdpqwmZO0QLCJUYXzcvunxrjft/\
\\|()1{}[]?-_+~<>i!lI;:,\"^`'.  ")

WIDTH = 120
HEIGHT = 60


# 将256个灰度值映射到字符列表中的字符
def get_char_from_pixel(r, g, b, alpha=256):
    if alpha == 0:
        return ' '
    length = len(ascii_char)
    gray = int(0.2126 * r + 0.7152 * g + 0.0722 * b)

    unit = (256.0 + 1)/length
    return ascii_char[int(gray/unit)]


# 使用PIL库对图片进行转换
def ascii_pic_from_pil(path):
    text = ""

    im = Image.open(path)
    im = im.resize((WIDTH, HEIGHT), Image.NEAREST)

    for h in range(im.size[1]):     # 图片像素纵坐标
        for w in range(im.size[0]): # 图片像素横坐标
            text += get_char_from_pixel(*im.getpixel((w, h)))
        text += '\n'

    return text


# 保存txt文件
def save_to_file(filename, pic_str):
    with open(filename, 'w') as f:
        f.write(pic_str)


img = ascii_pic_from_pil('huiyuan.jpg')
save_to_file('pil.txt', img)

'''
import cv2                # 引入opencv库
# 使用cv库对图片进行转换
def ascii_pic_from_cv(path):
    text = ""

    img = cv2.imread(path)
    img = cv2.resize(img, (WIDTH, HEIGHT))

    for h in range(HEIGHT):        # 图片像素纵坐标
        for w in range(WIDTH):    # 图片像素横坐标
            b, g, r = img[h,w]
            text += get_char_from_pixel(r,g,b)
        text += '\n'

    return text

img = ascii_pic_from_pil('huiyuan.jpg')
save_to_file('cv.txt', img)
'''
