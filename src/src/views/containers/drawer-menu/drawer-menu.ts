import { DrawerState } from '@/store/modules/app/state';
import TfeIconButton from '@components/icon-button/icon-button.vue';
import { defineComponent } from 'vue';
import { mapGetters } from 'vuex';

export default defineComponent({
  components: { TfeIconButton },
  data: () => ({ DrawerStateType: DrawerState }),
  computed: {
    ...mapGetters('self', ['username', 'email']),
    ...mapGetters('app', ['drawerState'])
  }
});
