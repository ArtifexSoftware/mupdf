package kankan.wheel.widget.adapters;

import android.content.Context;
import android.graphics.Color;
import android.widget.TextView;

public class ArrayWheelAdapterColor<T> extends AbstractWheelTextAdapter {

    // items
    private T items[];

    public ArrayWheelAdapterColor(Context context, T items[]) {
        super(context);

        this.items = items;
    }

    @Override
    public CharSequence getItemText(int index) {
        if (index >= 0 && index < items.length) {
            T item = items[index];
            if (item instanceof CharSequence) {
                return (CharSequence) item;
            }
            return item.toString();
        }
        return null;
    }

    @Override
    public int getItemsCount() {
        return items.length;
    }

    @Override
    protected void configureTextView(TextView view) {
        super.configureTextView(view);

        //  if the text ends with "(red)"
        //  color it red.
        String text = view.getText().toString();
        if (text.endsWith("(red)"))
        {
            text = text.replace("(red)","");
            view.setText(text);
            view.setTextColor(Color.parseColor("#ff0000"));
        }
    }

}