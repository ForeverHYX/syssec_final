# 期末汇报 Slides

`final_presentation.tex` 使用 ZJU Beamer Template 编写，模板来源：
<https://github.com/qychen2001/ZJU-Beamer-Template>

本目录中的 `zju_beamer.sty`、`figures/background.png`、`figures/logo.pdf` 和
`figures/char.pdf` 来自该模板仓库，并保留原模板文件中的许可证与作者声明。

`figures/apk_static_analysis_cutaway.png` 使用内置 image generation 工具生成，
只作为 APK 拆解对象的复杂示意图；框架、数据集矩阵和 benchmark 指标均由
LaTeX/TikZ/表格渲染，保证文字可读且内容可控。生成与落库记录见 `progress.md`。

编译方式：

```bash
make slides
```

生成的 PDF 和 LaTeX 辅助文件属于构建产物，已在仓库 `.gitignore` 中忽略。
