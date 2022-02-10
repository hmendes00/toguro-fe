<template>
  <div ref="root" class="custom-page-app"></div>
</template>

<style lang="scss" src="./custom-page-app.scss" scoped></style>
<script setup lang="ts">
  import { onBeforeMount, ref } from 'vue';
  import { computed, onMounted } from 'vue';
  import { appStore } from '@/store';
  import { onBeforeRouteUpdate, useRoute } from 'vue-router';
  import CustomAppService from '@/services/custom-app-service';

  const root = ref<HTMLElement | null>(null);
  const route = useRoute();
  const appId = ref('');
  appId.value = route.params['appId']?.toString();
  const customApp = computed(() => appStore.state.customApps[appId.value || -1]);
  const addCustomAppTag = () => {
    if (root.value) {
      root.value.innerHTML = `<${customApp.value.appName} />`;
    }
  };

  onMounted(() => {
    addCustomAppTag();
  });

  onBeforeMount(() => {
    CustomAppService.addScriptToHead(customApp.value);
  });

  onBeforeRouteUpdate((to) => {
    appId.value = to.params['appId']?.toString();
    addCustomAppTag();
    CustomAppService.addScriptToHead(customApp.value);
  });
</script>
