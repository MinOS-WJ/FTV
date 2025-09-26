### FTV
#### 一、功能概述 (Function Overview)
`FTV.py` 是一个基于 Python 的 GUI 应用程序，核心功能是实现“文件与视频的双向转换”，并支持可选加密/解密。  
`FTV.py` is a Python-based GUI application whose core function is to realize "bidirectional conversion between files and videos" with optional encryption/decryption.  

具体功能 (Specific functions)：
- **编码（Encode）**：将任意格式的文件（如文档、压缩包等）转换为视频文件（.mkv 格式），过程中可对文件数据进行加密。  
  Convert files of any format (e.g., documents, compressed packages) into video files (.mkv format), with optional data encryption during the process.  
- **解码（Decode）**：将通过该程序编码生成的视频文件还原为原始文件，若编码时加密，需输入对应密码解密。  
  Restore video files encoded by this program to their original files. If encrypted during encoding, the corresponding password is required for decryption.  

程序依赖库 (Dependent libraries)：`tkinter`（GUI 构建）、`OpenCV`（视频帧处理）、`NumPy`（数据与图像转换）、`PyCryptodome`（加密解密）。  
It relies on libraries such as `tkinter` (GUI construction), `OpenCV` (video frame processing), `NumPy` (data-image conversion), and `PyCryptodome` (encryption/decryption).  


#### 二、核心类与初始化 (Core Class & Initialization)
程序核心逻辑封装在 `FileToVideoConverter` 类中，初始化方法（`__init__`）完成以下工作：  
The core logic is encapsulated in the `FileToVideoConverter` class. The initialization method (`__init__`) performs the following tasks:  

1. **窗口设置（Window Setup）**：创建主窗口，标题为“文件转视频编码器/解码器(加密可选)”，初始大小 800x750，支持缩放。  
   Create a main window with the title "文件转视频编码器/解码器(加密可选)" (File to Video Encoder/Decoder with Optional Encryption), initial size 800x750, and resizable.  

2. **界面框架（UI Framework）**：使用 `ttk.Notebook` 创建“编码”和“解码”两个标签页，分别通过 `create_encode_ui` 和 `create_decode_ui` 方法构建界面元素。  
   Use `ttk.Notebook` to create two tabs: "编码" (Encode) and "解码" (Decode), with UI elements built by `create_encode_ui` and `create_decode_ui` methods, respectively.  

3. **状态变量（State Variables）**：定义编码/解码状态（`encoding`/`decoding`）、计时与进度相关变量（如 `encode_start_time` 用于计算处理速度）。  
   Define encoding/decoding states (`encoding`/`decoding`) and timing/progress-related variables (e.g., `encode_start_time` for calculating processing speed).  


#### 三、界面设计（UI Design）
界面分为“编码”和“解码”两个标签页，布局均采用 `grid` 管理器。  
The UI is divided into two tabs ("Encode" and "Decode"), both using the `grid` layout manager.  


##### 1. 编码标签页（Encode Tab，`create_encode_ui` 方法）
核心元素（Core elements）：  
- **输入/输出选择（Input/Output Selection）**：  
  - 输入文件：文本框 + “浏览”按钮（调用 `browse_encode_input` 选择文件）。  
    Input file: Text box + "浏览..." (Browse) button (calls `browse_encode_input` to select files).  
  - 输出视频：文本框 + “浏览”按钮（调用 `browse_encode_output` 选择保存路径，默认 .mkv 格式）。  
    Output video: Text box + "浏览..." (Browse) button (calls `browse_encode_output` to select save path, default .mkv format).  

- **参数设置（Parameter Settings）**：  
  - 加密密码（可选）：密码框（显示为 `*`），提示“不填则不加密”。  
    Encryption password (optional): Password box (displays `*`), with the hint "不填则不加密" (No encryption if left blank).  
  - 帧率（fps）：文本框，默认值 10。  
    Frame rate (fps): Text box, default value 10.  
  - 图像尺寸：下拉框（可选 128x128 至 4096x4096），默认 256x256。  
    Image resolution: Dropdown menu (options from 128x128 to 4096x4096), default 256x256.  

- **信息与反馈（Information & Feedback）**：  
  - 文件信息标签：显示选中文件的名称和大小（字节/KB）。  
    File info label: Displays the name and size (bytes/KB) of the selected file.  
  - 预览区域：显示基于文件前 512 字节生成的图像预览（调用 `update_preview`）。  
    Preview area: Shows an image preview generated from the first 512 bytes of the file (via `update_preview`).  
  - 进度条：实时显示编码进度。  
    Progress bar: Real-time display of encoding progress.  
  - 速度标签：显示当前处理速度（MB/s）。  
    Speed label: Displays current processing speed (MB/s).  
  - 开始编码按钮：触发 `start_encoding` 方法（启动编码线程，避免 UI 卡顿）。  
    Start encoding button: Triggers `start_encoding` (starts an encoding thread to prevent UI freezing).  


##### 2. 解码标签页（Decode Tab，`create_decode_ui` 方法）
结构与编码页类似，核心元素包括（Similar structure to the Encode tab, with core elements）：  
- **输入/输出选择（Input/Output Selection）**：  
  - 视频文件：文本框 + “浏览”按钮（调用 `browse_decode_input` 选择 .mkv 视频）。  
    Video file: Text box + "浏览..." (Browse) button (calls `browse_decode_input` to select .mkv videos).  
  - 输出文件夹：文本框 + “浏览”按钮（调用 `browse_decode_output` 选择保存路径）。  
    Output folder: Text box + "浏览..." (Browse) button (calls `browse_decode_output` to select save path).  

- **参数设置（Parameter Settings）**：  
  - 解密密码（可选）：密码框，提示“加密时填写的密码”。  
    Decryption password (optional): Password box, with the hint "加密时填写的密码" (Password used for encryption).  

- **信息与反馈（Information & Feedback）**：  
  - 预览区域：显示视频第一帧的灰度预览（调用 `update_decode_preview`）。  
    Preview area: Shows a grayscale preview of the first video frame (via `update_decode_preview`).  
  - 进度条与速度标签：功能同编码页。  
    Progress bar and speed label: Same functionality as in the Encode tab.  
  - 开始解码按钮：触发 `start_decoding` 方法（启动解码线程）。  
    Start decoding button: Triggers `start_decoding` (starts a decoding thread).  


#### 四、核心功能实现（Core Function Implementation）


##### 1. 文件与视频的转换逻辑（File-Video Conversion Logic）
核心是“将文件数据编码为视频帧”和“从视频帧提取数据还原文件”，依赖数据与图像的相互转换。  
The core lies in "encoding file data into video frames" and "extracting data from video frames to restore files", relying on data-image mutual conversion.  

- **数据转图像（`create_image_from_data` 方法）**：  
  - 根据选中的图像尺寸（如 256x256）计算单帧可存储的字节数（`width * height // 8`，因每个像素用 1 位表示，8 位=1 字节）。  
    Calculate the number of bytes storable per frame based on the selected resolution (e.g., 256x256) as `width * height // 8` (each pixel uses 1 bit; 8 bits = 1 byte).  
  - 将输入数据填充或截断至单帧字节数，通过 `np.unpackbits` 转换为二进制位数组。  
    Pad or truncate input data to match the per-frame byte count, then convert to a binary bit array via `np.unpackbits`.  
  - 将位数组重塑为图像尺寸的二维数组，乘以 255 转为 0-255 灰度值（二值图像：0 或 255）。  
    Reshape the bit array into a 2D array matching the image resolution, multiply by 255 to convert to 0-255 grayscale values (binary image: 0 or 255).  

- **图像提数据（`extract_data_from_image` 方法）**：  
  - 将视频帧转为灰度图，通过阈值处理（`cv2.threshold`）转为二值图像（0 或 255）。  
    Convert the video frame to grayscale, then to a binary image (0 or 255) via thresholding (`cv2.threshold`).  
  - 将像素值归一化（除以 255 得 0 或 1），通过 `np.packbits` 转换为字节数据。  
    Normalize pixel values (divide by 255 to get 0 or 1), then convert to byte data via `np.packbits`.  


##### 2. 编码流程（Encoding Process，`encode_file_to_video` 方法）
将文件转换为视频的步骤（Steps to convert a file to a video）：  
1. **参数解析（Parameter Parsing）**：获取图像尺寸、帧率、密码（判断是否加密）。  
   Retrieve image resolution, frame rate, and password (to determine if encryption is needed).  

2. **数据预处理（Data Preprocessing）**：  
   - 读取原始文件数据，计算 SHA256 哈希（用于解码时验证完整性）。  
     Read raw file data and compute its SHA256 hash (for integrity verification during decoding).  
   - 若加密：使用 `encrypt_data` 方法对文件数据进行 AES-CBC 加密（生成随机盐和 IV，密钥通过 PBKDF2 从密码派生）。  
     If encrypted: Encrypt file data with AES-CBC via `encrypt_data` (generates random salt and IV; key derived from the password using PBKDF2).  
   - 若不加密：直接使用原始文件数据。  
     If unencrypted: Use raw file data directly.  

3. **数据结构封装（Data Structure Encapsulation）**：确保解码时能正确解析，格式为：  
   To ensure correct parsing during decoding, data is encapsulated as:  
   ```
   [加密标志(1字节)] + [SHA256哈希(32字节)] + [文件名长度(4字节)] + [文件名(字节)] + [数据长度(8字节)] + [处理后的数据(加密/原始)]
   [Encryption flag (1 byte)] + [SHA256 hash (32 bytes)] + [Filename length (4 bytes)] + [Filename (bytes)] + [Data length (8 bytes)] + [Processed data (encrypted/raw)]
   ```  
   - 加密标志：1 表示加密，0 表示不加密。  
     Encryption flag: 1 for encrypted, 0 for unencrypted.  
   - 文件名长度/数据长度：用大端字节序存储，确保跨平台解析一致。  
     Filename length/data length: Stored in big-endian byte order for cross-platform consistency.  

4. **视频生成（Video Generation）**：  
   - 计算单帧有效数据量（单帧总字节数 - 16 字节帧头，帧头用于存储当前帧数据长度）。  
     Calculate effective data per frame (total per-frame bytes - 16-byte header, where the header stores current frame data length).  
   - 按单帧有效数据量拆分总数据，计算总帧数。  
     Split total data by effective per-frame data size and calculate total frames.  
   - 使用 `cv2.VideoWriter` 创建视频（编码格式 FFV1，需 FFmpeg 支持），逐帧将数据转换为图像并写入视频。  
     Create a video using `cv2.VideoWriter` (FFV1 codec, requires FFmpeg support), convert data to images frame-by-frame, and write to the video.  

5. **进度与速度更新（Progress & Speed Update）**：实时计算处理进度和速度，通过 UI 反馈。  
   Real-time calculation of processing progress and speed, with feedback via the UI.  


##### 3. 解码流程（Decoding Process，`decode_video_to_file` 方法）
将视频还原为文件的步骤（Steps to restore a video to a file）：  
1. **视频读取（Video Reading）**：使用 `cv2.VideoCapture` 打开视频，获取总帧数。  
   Open the video with `cv2.VideoCapture` and retrieve the total number of frames.  

2. **数据提取（Data Extraction）**：逐帧读取视频帧，通过 `extract_data_from_image` 提取数据，忽略帧头（前 16 字节），合并所有有效数据。  
   Read video frames one by one, extract data via `extract_data_from_image`, ignore the 16-byte header, and merge all valid data.  

3. **数据解析（Data Parsing）**：按编码时的固定格式解析合并后的数据（提取加密标志、哈希、文件名等）。  
   Parse merged data according to the encoding format (extract encryption flag, hash, filename, etc.).  

4. **数据还原（Data Restoration）**：  
   - 若加密：使用 `decrypt_data` 方法解密（需输入正确密码，通过盐和 IV 派生密钥）。  
     If encrypted: Decrypt via `decrypt_data` (requires correct password; key derived using salt and IV).  
   - 若不加密：直接使用提取的原始数据。  
     If unencrypted: Use extracted raw data directly.  

5. **完整性验证（Integrity Verification）**：计算还原后数据的 SHA256 哈希，与编码时存储的哈希比对。  
   Compute the SHA256 hash of the restored data and compare it with the hash stored during encoding.  

6. **文件写入（File Writing）**：将还原的数据写入输出文件夹，文件名与原始文件一致。  
   Write the restored data to the output folder with the original filename.  


##### 4. 加密与解密（Encryption & Decryption，基于 `PyCryptodome`）
- **密钥派生（`derive_key` 方法）**：使用 PBKDF2 算法，从密码和随机盐生成 32 字节（256 位）AES 密钥（迭代次数 1,000,000 次）。  
  Key derivation (`derive_key` method): Uses PBKDF2 to generate a 32-byte (256-bit) AES key from the password and random salt (1,000,000 iterations).  

- **加密（`encrypt_data` 方法）**：  
  - 生成 16 字节随机盐和 AES 块大小（16 字节）的 IV（初始向量）。  
    Generate a 16-byte random salt and a 16-byte IV (initialization vector) matching the AES block size.  
  - 使用 AES-CBC 模式加密数据，自动填充至块大小的整数倍（PKCS#7 填充）。  
    Encrypt data in AES-CBC mode, with automatic padding to a multiple of the block size (PKCS#7 padding).  
  - 输出格式：`盐 + IV + 加密后的数据`（解密时需用盐和 IV 还原密钥和初始状态）。  
    Output format: `salt + IV + encrypted data` (salt and IV are needed for key recovery and initialization during decryption).  

- **解密（`decrypt_data` 方法）**：  
  - 从加密数据中提取盐和 IV，派生密钥。  
    Extract salt and IV from encrypted data, then derive the key.  
  - 解密后去除填充，还原原始数据。  
    Remove padding after decryption to restore raw data.  


#### 五、用户交互细节（User Interaction Details）
1. **预览功能（Preview Function）**：  
   - 编码预览：选择文件后，基于前 512 字节生成图像预览，直观展示数据转图像的效果。  
     Encode preview: After selecting a file, generate an image preview from the first 512 bytes to visualize data-to-image conversion.  
   - 解码预览：选择视频后，显示第一帧的灰度图，确认视频有效性。  
     Decode preview: After selecting a video, display a grayscale image of the first frame to verify video validity.  

2. **进度与速度反馈（Progress & Speed Feedback）**：  
   - 进度条实时更新处理进度（0-100%）。  
     Progress bar updates in real time (0-100%).  
   - 每 1 秒更新一次处理速度（MB/s），提升用户对处理过程的感知。  
     Processing speed (MB/s) updates every 1 second to enhance user awareness of the process.  

3. **异常处理（Error Handling）**：通过 `messagebox` 提示错误（如文件无法读取、密码错误、视频损坏等）。  
   Error prompts via `messagebox` (e.g., unreadable files, incorrect passwords, corrupted videos).  


#### 六、依赖与限制（Dependencies & Limitations）
- **依赖库（Dependent Libraries）**：`tkinter`、`numpy`、`cv2`、`PIL`、`PyCryptodome`。  
- **视频编码（Video Codec）**：使用 FFV1 编码（无损压缩），需系统安装支持该编码的 FFmpeg，否则可能无法创建视频。  
  Uses FFV1 codec (lossless compression); requires FFmpeg with FFV1 support installed, otherwise video creation may fail.  

- **性能考量（Performance Considerations）**：图像尺寸越大（如 4096x4096），单帧存储数据越多，总帧数越少，但视频文件体积越大；帧率影响视频播放速度，不影响数据存储量。  
  Larger resolutions (e.g., 4096x4096) store more data per frame, reducing total frames but increasing video size; frame rate affects playback speed but not data storage.  

- **加密安全性（Encryption Security）**：AES-256 加密结合高迭代次数的 PBKDF2，安全性较高，但密码强度直接影响加密效果（弱密码易被破解）。  
  AES-256 encryption with high-iteration PBKDF2 offers strong security, but password strength directly impacts effectiveness (weak passwords are vulnerable to cracking).  


#### 总结（Summary）
`FTV.py` 实现了一种新颖的“文件-视频”转换方案，通过将文件数据嵌入视频帧，实现了文件的“伪装”存储，同时支持加密保护。程序界面直观，功能完整，适合需要隐蔽存储或传输文件的场景（需注意视频文件体积通常远大于原始文件）。  
`FTV.py` implements a novel "file-to-video" conversion scheme, enabling "disguised" storage of files by embedding data into video frames, with optional encryption. The program has an intuitive interface and complete functionality, suitable for scenarios requiring covert file storage or transmission (note that video files are typically much larger than original files).
