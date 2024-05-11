<script setup>

</script>

<template>
  <div style="width: 100vw;height: 100vh;overflow: hidden;display: flex">
    <div style="flex: 1;background-color: cornflowerblue">
      <el-image style="=width: 100%;height: 100%" fit="cover"
          src="https://gimg2.baidu.com/image_search/src=http%3A%2F%2Fimage109.360doc.com%2FDownloadImg%2F2023%2F09%2F0411%2F271753575_1_20230904110453291&refer=http%3A%2F%2Fimage109.360doc.com&app=2002&size=f9999,10000&q=a80&n=0&g=0n&fmt=auto?sec=1718022386&t=1ddf812c99aa9208ee9526a5eaa775ce"/>

    </div>
    <div class="welcome-title">
      <div style="font-size: 30px;font-weight: bold"> 欢迎</div>
      <div style="margin-top: 10px"> 学习</div>
      <div style="margin-top: 5px"> ---</div>



    </div>
    <div class="right-card">

    </div>

  </div>

</template>

<style scoped>
.welcome-title{
  position: absolute;
  bottom: 30px;
  left: 30px;
  color: white;
  text-shadow: 0 0 10px black;
}
.right-card{
  width: 400px;
  z-index: 1;
  background-color: white;
}

</style>