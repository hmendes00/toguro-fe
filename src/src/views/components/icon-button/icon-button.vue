<template>
  <div class="tfe-icon-button">
    <div v-if="leftText">{{ leftText }}</div>
    <div class="icon"><slot></slot></div>
    <div v-if="rightText">{{ rightText }}</div>
  </div>
</template>

<style lang="scss" src="./icon-button.scss" scoped></style>
<script type="typescript" src="./icon-button.ts"></script>
