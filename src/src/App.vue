<template>
  <div class="tfe-app">
    <tfe-default-layout />
  </div>
</template>

<script lang="ts">
  import TfeDefaultLayout from '@layouts/default/default.vue';

  export default {
    components: { TfeDefaultLayout }
  };
</script>

<style lang="scss">
  @import '@styles/reset.scss';

  .tfe-app {
    // font-family: Roboto, 'Helvetica Neue', Helvetica, Arial, sans-serif;
  }
</style>
