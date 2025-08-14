import numpy as np
import cv2
import matplotlib.pyplot as plt
from skimage.util import random_noise
from scipy.fftpack import dct, idct
from sklearn.metrics import normalized_mutual_information


class ImageWatermarker:
    def __init__(self, watermark_intensity=0.1, block_size=8):
        """
        初始化水印系统
        :param watermark_intensity: 水印嵌入强度 (0-1)
        :param block_size: DCT块大小
        """
        self.watermark_intensity = watermark_intensity
        self.block_size = block_size
        self.watermark_size = None
        self.key = None

    def generate_watermark(self, size):
        """
        生成随机二值水印
        :param size: 水印尺寸 (height, width)
        :return: 二值水印图像
        """
        self.watermark_size = size
        # 生成随机水印，使用固定种子确保可重现性
        np.random.seed(42)
        return np.random.randint(0, 2, size).astype(np.uint8)

    def embed_watermark(self, host_image, watermark):
        """
        将水印嵌入到宿主图像中
        :param host_image: 宿主图像 (BGR格式)
        :param watermark: 二值水印图像
        :return: 含水印的图像
        """
        if host_image is None:
            raise ValueError("宿主图像为空")

        if watermark is None:
            raise ValueError("水印为空")

        # 保存水印尺寸用于提取
        self.watermark_size = watermark.shape

        # 转换到YUV颜色空间，在Y通道嵌入水印
        yuv_image = cv2.cvtColor(host_image, cv2.COLOR_BGR2YUV)
        y_channel = yuv_image[:, :, 0].astype(np.float32)

        # 存储原始Y通道用于生成密钥
        original_y = y_channel.copy()

        # 创建水印图像副本
        watermarked_image = host_image.copy()
        watermarked_y = y_channel.copy()

        # 确保水印可以被分成8x8块
        h, w = y_channel.shape
        wm_h, wm_w = watermark.shape

        # 计算每个水印块对应的宿主图像块数
        blocks_per_row = w // self.block_size
        blocks_per_col = h // self.block_size

        # 确保宿主图像足够大
        if blocks_per_row < wm_w or blocks_per_col < wm_h:
            raise ValueError("宿主图像太小，无法嵌入水印")

        # 计算每个水印位对应的宿主图像块
        block_step_x = blocks_per_row // wm_w
        block_step_y = blocks_per_col // wm_h

        # 生成密钥 - 记录水印嵌入位置
        self.key = []

        # 在DCT域嵌入水印
        for i in range(wm_h):
            for j in range(wm_w):
                # 计算宿主图像块的位置
                block_x = j * block_step_x
                block_y = i * block_step_y

                # 随机选择块内的位置
                pos_x = block_x * self.block_size + np.random.randint(0, self.block_size)
                pos_y = block_y * self.block_size + np.random.randint(0, self.block_size)

                # 记录密钥
                self.key.append((pos_y, pos_x))

                # 获取8x8块
                block = watermarked_y[pos_y:pos_y + self.block_size, pos_x:pos_x + self.block_size]

                # 应用DCT变换
                dct_block = dct(dct(block, axis=0, norm='ortho'), axis=1, norm='ortho')

                # 选择中频系数嵌入水印
                # 通常选择(3,4)位置，避开高频和低频
                coeff_y, coeff_x = 3, 4

                # 嵌入水印位
                if watermark[i, j] == 1:
                    dct_block[coeff_y, coeff_x] += self.watermark_intensity * dct_block[coeff_y, coeff_x]
                else:
                    dct_block[coeff_y, coeff_x] -= self.watermark_intensity * dct_block[coeff_y, coeff_x]

                # 应用逆DCT
                idct_block = idct(idct(dct_block, axis=0, norm='ortho'), axis=1, norm='ortho')

                # 更新图像块
                watermarked_y[pos_y:pos_y + self.block_size, pos_x:pos_x + self.block_size] = idct_block

        # 将修改后的Y通道合并回YUV图像
        yuv_image[:, :, 0] = watermarked_y

        # 转换回BGR
        watermarked_image = cv2.cvtColor(yuv_image, cv2.COLOR_YUV2BGR)

        # 计算PSNR
        psnr = self.calculate_psnr(host_image, watermarked_image)
        print(f"水印嵌入完成，PSNR: {psnr:.2f} dB")

        return watermarked_image

    def extract_watermark(self, watermarked_image):
        """
        从含水印图像中提取水印
        :param watermarked_image: 含水印的图像
        :return: 提取的水印图像
        """
        if watermarked_image is None:
            raise ValueError("含水印图像为空")

        if self.key is None or self.watermark_size is None:
            raise RuntimeError("请先嵌入水印或提供密钥和水印尺寸")

        # 转换到YUV颜色空间
        yuv_image = cv2.cvtColor(watermarked_image, cv2.COLOR_BGR2YUV)
        y_channel = yuv_image[:, :, 0].astype(np.float32)

        # 创建空水印
        watermark = np.zeros(self.watermark_size, dtype=np.uint8)

        # 提取水印
        idx = 0
        for i in range(self.watermark_size[0]):
            for j in range(self.watermark_size[1]):
                # 获取嵌入位置
                pos_y, pos_x = self.key[idx]
                idx += 1

                # 获取8x8块
                block = y_channel[pos_y:pos_y + self.block_size, pos_x:pos_x + self.block_size]

                # 应用DCT变换
                dct_block = dct(dct(block, axis=0, norm='ortho'), axis=1, norm='ortho')

                # 选择中频系数
                coeff_y, coeff_x = 3, 4
                coeff_value = dct_block[coeff_y, coeff_x]

                # 提取水印位
                if coeff_value > 0:
                    watermark[i, j] = 1
                else:
                    watermark[i, j] = 0

        return watermark

    def calculate_psnr(self, img1, img2):
        """
        计算两幅图像的PSNR(峰值信噪比)
        :param img1: 图像1
        :param img2: 图像2
        :return: PSNR值
        """
        if img1.shape != img2.shape:
            raise ValueError("图像尺寸不匹配")

        # 将图像转换为浮点数
        img1 = img1.astype(np.float32)
        img2 = img2.astype(np.float32)

        # 计算MSE
        mse = np.mean((img1 - img2) ** 2)

        # 避免除以零
        if mse == 0:
            return float('inf')

        # 计算PSNR
        max_pixel = 255.0
        psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
        return psnr

    def calculate_similarity(self, watermark1, watermark2):
        """
        计算两个水印的相似度
        :param watermark1: 水印1
        :param watermark2: 水印2
        :return: 相似度 (0-1)
        """
        if watermark1.shape != watermark2.shape:
            raise ValueError("水印尺寸不匹配")

        # 计算比特错误率
        error_rate = np.mean(watermark1 != watermark2)

        # 计算相似度
        similarity = 1 - error_rate
        return similarity

    def apply_attacks(self, watermarked_image):
        """
        应用各种攻击来测试水印鲁棒性
        :param watermarked_image: 含水印的图像
        :return: 攻击后的图像列表和攻击名称列表
        """
        attacked_images = []
        attack_names = []

        # 原始图像
        attacked_images.append(watermarked_image)
        attack_names.append("原始图像")

        # 1. 添加高斯噪声
        noisy_image = random_noise(watermarked_image, mode='gaussian', var=0.01)
        noisy_image = (noisy_image * 255).astype(np.uint8)
        attacked_images.append(noisy_image)
        attack_names.append("高斯噪声")

        # 2. JPEG压缩
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 50]
        _, jpeg_encoded = cv2.imencode('.jpg', watermarked_image, encode_param)
        jpeg_image = cv2.imdecode(jpeg_encoded, 1)
        attacked_images.append(jpeg_image)
        attack_names.append("JPEG压缩")

        # 3. 水平翻转
        flipped_image = cv2.flip(watermarked_image, 1)
        attacked_images.append(flipped_image)
        attack_names.append("水平翻转")

        # 4. 旋转
        rows, cols = watermarked_image.shape[:2]
        M = cv2.getRotationMatrix2D((cols / 2, rows / 2), 5, 1)  # 旋转5度
        rotated_image = cv2.warpAffine(watermarked_image, M, (cols, rows))
        attacked_images.append(rotated_image)
        attack_names.append("旋转5度")

        # 5. 裁剪
        cropped_image = watermarked_image[50:-50, 50:-50]
        cropped_image = cv2.resize(cropped_image, (cols, rows))
        attacked_images.append(cropped_image)
        attack_names.append("裁剪边缘")

        # 6. 调整对比度
        # 转换为YUV，调整Y通道对比度，再转回BGR
        yuv_img = cv2.cvtColor(watermarked_image, cv2.COLOR_BGR2YUV)
        yuv_img[:, :, 0] = cv2.equalizeHist(yuv_img[:, :, 0])
        contrast_image = cv2.cvtColor(yuv_img, cv2.COLOR_YUV2BGR)
        attacked_images.append(contrast_image)
        attack_names.append("对比度调整")

        # 7. 模糊
        blurred_image = cv2.GaussianBlur(watermarked_image, (5, 5), 0)
        attacked_images.append(blurred_image)
        attack_names.append("高斯模糊")

        # 8. 缩放
        scaled_image = cv2.resize(watermarked_image, None, fx=0.5, fy=0.5)
        scaled_image = cv2.resize(scaled_image, (cols, rows))
        attacked_images.append(scaled_image)
        attack_names.append("缩放50%")

        # 9. 亮度调整
        bright_image = cv2.convertScaleAbs(watermarked_image, alpha=1.2, beta=20)
        attacked_images.append(bright_image)
        attack_names.append("亮度增加")

        return attacked_images, attack_names


def display_images(images, titles, rows, cols, figsize=(15, 10)):
    """显示多幅图像"""
    plt.figure(figsize=figsize)
    for i in range(len(images)):
        plt.subplot(rows, cols, i + 1)
        if len(images[i].shape) == 2:  # 灰度图像
            plt.imshow(images[i], cmap='gray')
        else:  # 彩色图像
            # 转换BGR到RGB
            plt.imshow(cv2.cvtColor(images[i], cv2.COLOR_BGR2RGB))
        plt.title(titles[i])
        plt.axis('off')
    plt.tight_layout()
    plt.show()


def main():
    # 1. 加载宿主图像
    host_image = cv2.imread('host_image.jpg')  # 替换为你的图像路径
    if host_image is None:
        # 如果找不到图像，创建一个示例图像
        host_image = np.zeros((512, 512, 3), dtype=np.uint8)
        cv2.putText(host_image, 'Sample Host Image', (50, 256),
                    cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)

    # 2. 创建水印器
    watermarker = ImageWatermarker(watermark_intensity=0.15)

    # 3. 生成水印 (尺寸为宿主图像的1/8)
    watermark_size = (host_image.shape[0] // 8, host_image.shape[1] // 8)
    watermark = watermarker.generate_watermark(watermark_size)

    # 4. 嵌入水印
    watermarked_image = watermarker.embed_watermark(host_image, watermark)

    # 5. 应用各种攻击
    attacked_images, attack_names = watermarker.apply_attacks(watermarked_image)

    # 6. 从攻击后的图像中提取水印并计算相似度
    extracted_watermarks = []
    similarities = []

    for i, img in enumerate(attacked_images):
        try:
            extracted_wm = watermarker.extract_watermark(img)
            similarity = watermarker.calculate_similarity(watermark, extracted_wm)
            similarities.append(similarity)

            # 为显示准备水印
            extracted_watermarks.append(extracted_wm * 255)  # 转换为0-255范围

            print(f"{attack_names[i]}: 相似度 = {similarity:.4f}")
        except Exception as e:
            print(f"处理 {attack_names[i]} 时出错: {str(e)}")
            similarities.append(0)
            extracted_watermarks.append(np.zeros(watermark_size, dtype=np.uint8))

    # 7. 显示结果
    # 显示原始图像和水印
    display_images(
        [host_image, watermark * 255, watermarked_image],
        ['原始图像', '水印', '含水印的图像'],
        1, 3, figsize=(15, 5)
    )

    # 显示攻击后的图像
    display_images(
        attacked_images,
        attack_names,
        3, 3,
        figsize=(15, 15)
    )

    # 显示提取的水印
    display_images(
        extracted_watermarks,
        [f"{name}\n相似度: {sim:.4f}" for name, sim in zip(attack_names, similarities)],
        3, 3,
        figsize=(15, 15)
    )

    # 绘制鲁棒性测试结果
    plt.figure(figsize=(12, 6))
    plt.bar(attack_names, similarities, color='skyblue')
    plt.axhline(y=0.75, color='r', linestyle='--', label='可接受阈值')
    plt.title('水印鲁棒性测试')
    plt.ylabel('相似度')
    plt.xticks(rotation=45, ha='right')
    plt.ylim(0, 1.05)
    plt.legend()
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()