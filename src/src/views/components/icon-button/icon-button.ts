import { defineComponent } from 'vue';

export default defineComponent({
  props: {
    rightText: {
      type: String,
      default: ''
    },
    leftText: {
      type: String,
      default: ''
    }
  }
});
