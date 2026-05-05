#!/usr/bin/env python3
"""
Android Project Packer for AI Context (with comment stripping)
递归收集安卓项目中的源代码与配置文件，合并为一个文本文件，
自动排除构建产物、二进制文件及常见无关目录，并可选择移除注释。
"""

import os
import sys
import argparse
import fnmatch
import re
from pathlib import Path

# 默认排除的目录（支持通配符）
DEFAULT_EXCLUDE_DIRS = [
    'build', '.gradle', '.idea', '.git', '__pycache__', 'node_modules',
    'app/build', 'app/.cxx', 'app/obj', '.externalNativeBuild', '.cxx',
    '.vscode', '.settings', '.DS_Store'
]

# 默认排除的文件（支持通配符）
DEFAULT_EXCLUDE_FILES = [
    '*.apk', '*.dex', '*.class', '*.jar', '*.aar', '*.so', '*.o',
    '*.png', '*.jpg', '*.jpeg', '*.gif', '*.ico', '*.webp',
    '*.mp4', '*.mp3', '*.wav', '*.ttf', '*.otf',
    '*.db', '*.sqlite', '*.iml', '*.lock', '*.log',
    '*.zip', '*.tar', '*.gz', '*.7z',
    '*.DS_Store', '*.swp', '*.swo', '*.swn'
]

# 默认包含的文件扩展名（只处理这些文本文件）
DEFAULT_INCLUDE_EXTENSIONS = [
    '.java', '.kt', '.kts', '.xml', '.gradle', '.properties', '.pro',
    '.txt', '.md', '.json', '.yml', '.yaml', '.cfg', '.ini', '.rc', '.cpp', '.hpp'
]

def should_exclude_dir(dir_path, exclude_dirs):
    """判断目录是否应该被排除"""
    dir_name = os.path.basename(dir_path)
    for pattern in exclude_dirs:
        if fnmatch.fnmatch(dir_name, pattern) or fnmatch.fnmatch(dir_path, pattern):
            return True
    return False

def should_exclude_file(file_rel_path, exclude_files):
    """判断文件是否应该被排除"""
    file_name = os.path.basename(file_rel_path)
    for pattern in exclude_files:
        if fnmatch.fnmatch(file_name, pattern) or fnmatch.fnmatch(file_rel_path, pattern):
            return True
    return False

def collect_files(root_dir, include_extensions, exclude_dirs, exclude_files):
    """遍历目录，收集符合条件的文件"""
    collected = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 原地修改dirnames，跳过要排除的子目录
        dirnames[:] = [d for d in dirnames if not should_exclude_dir(os.path.join(dirpath, d), exclude_dirs)]
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(full_path, root_dir)
            if should_exclude_file(rel_path, exclude_files):
                continue
            ext = os.path.splitext(filename)[1].lower()
            if include_extensions and ext not in include_extensions:
                continue
            collected.append((rel_path, full_path))
    return collected

def remove_comments(content, ext, keep_comments=False):
    """
    根据文件扩展名移除注释
    如果 keep_comments 为 True，则原样返回
    """
    if keep_comments:
        return content

    # Java/Kotlin/Groovy 风格注释
    if ext in ['.java', '.kt', '.kts', '.gradle', '.groovy']:
        # 移除多行注释 /* ... */ （包括文档注释）
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        # 移除单行注释 //
        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
    # XML/HTML 注释
    elif ext in ['.xml', '.html', '.htm']:
        content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)
    # Properties / YAML 注释（行首 #）
    elif ext in ['.properties', '.yml', '.yaml']:
        content = re.sub(r'^\s*#.*$', '', content, flags=re.MULTILINE)
    # 其他扩展名暂不处理

    # 可选：去除多余的空行（保留一个空行分隔逻辑块）
    # 可根据需要启用，但可能会破坏格式，暂时保留原样
    return content

def write_output(collected, output_file, keep_comments):
    """将收集到的文件内容合并写入输出文件，可选择移除注释"""
    with open(output_file, 'w', encoding='utf-8') as out:
        for rel_path, full_path in collected:
            out.write(f"===== File: {rel_path} =====\n")
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                ext = os.path.splitext(full_path)[1].lower()
                content = remove_comments(content, ext, keep_comments)
                out.write(content)
                out.write("\n\n")
            except Exception as e:
                out.write(f"Error reading file: {e}\n\n")

def main():
    parser = argparse.ArgumentParser(
        description='Pack Android project source files into a single text file for AI analysis.'
    )
    parser.add_argument('project_dir', help='Android项目根目录路径')
    parser.add_argument('-o', '--output', default='android_project_context.txt',
                        help='输出文件名 (默认: android_project_context.txt)')
    parser.add_argument('--include-ext', nargs='+', default=DEFAULT_INCLUDE_EXTENSIONS,
                        help=f'要包含的文件扩展名 (默认: {DEFAULT_INCLUDE_EXTENSIONS})')
    parser.add_argument('--exclude-dir', nargs='+', default=DEFAULT_EXCLUDE_DIRS,
                        help=f'要排除的目录名/模式 (默认: {DEFAULT_EXCLUDE_DIRS})')
    parser.add_argument('--exclude-file', nargs='+', default=DEFAULT_EXCLUDE_FILES,
                        help=f'要排除的文件名/模式 (默认: {DEFAULT_EXCLUDE_FILES})')
    parser.add_argument('--keep-comments', action='store_true',
                        help='保留代码中的注释（默认会移除注释以节省上下文）')

    args = parser.parse_args()

    project_dir = os.path.abspath(args.project_dir)
    if not os.path.isdir(project_dir):
        print(f"错误: {project_dir} 不是一个有效的目录")
        sys.exit(1)

    print(f"正在收集 {project_dir} 中的文件...")
    collected = collect_files(project_dir, set(args.include_ext), args.exclude_dir, args.exclude_file)
    print(f"找到 {len(collected)} 个文件")

    print(f"正在写入 {args.output} ...")
    write_output(collected, args.output, args.keep_comments)
    print("完成")

if __name__ == '__main__':
    main()