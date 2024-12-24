echo "Creating buildable source code archives..."
echo ""

archive_modules() {
    currpath=$(pwd)
    for i in $(git submodule status | cut -d " " -f 2,3 | sed "s/ /@/g"); do
        comm=$(echo $i | cut -d "@" -f 1)
        pth=$(echo $i | cut -d "@" -f 2)
        echo "    Archiving $pth @ $comm..."
        cd $pth
        git archive --prefix "$1/$pth/" -o $currpath/temp.tar $comm
        cd $currpath
        tar -n --concatenate --file=$1.tar temp.tar
        rm temp.tar
    done
}

archive_repo() {
    echo "Checking out $1"
    git checkout $1
    git submodule update --recursive
    echo "Archiving $1"
    git archive --prefix "mupdf-$1/" -o mupdf-$1.tar $1
    archive_modules mupdf-$1
    pigz mupdf-$1.tar
    echo "Done $1"
    echo ""
}

archive_repo win_x64
archive_repo win_x86
archive_repo win_arm
archive_repo linux_x64
archive_repo linux_arm64
archive_repo macOS

echo "Checking out master"
git checkout master
git submodule update --recursive
