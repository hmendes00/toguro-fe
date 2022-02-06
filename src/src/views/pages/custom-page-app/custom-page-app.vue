<template>
  <div ref="root" class="custom-page-app"></div>
</template>

<style lang="scss" src="./custom-page-app.scss" scoped></style>
<script setup lang="ts">
  import { onBeforeMount, ref } from 'vue';
  // import GsnIconButton from '@components/icon-button/icon-button.vue';
  import { computed, onMounted } from 'vue';
  import { appStore } from '@/store';
  import { useRoute } from 'vue-router';
  import CustomAppService from '@/services/custom-app-service';

  const root = ref<HTMLElement | null>(null);
  const route = useRoute();
  const customApp = computed(() => appStore.state.customApps[route.params['appId']?.toString() || -1]);

  onMounted(() => {
    if (root.value) {
      root.value.innerHTML = `<${customApp.value.appName} />`;
    }
  });

  onBeforeMount(() => {
    CustomAppService.addScriptToHead(customApp.value);
  });
</script>
