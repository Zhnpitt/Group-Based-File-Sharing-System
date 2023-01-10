public class Password {

    public static String getPassword(){
    String alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-=+!@#$%^&*(){}|?><:;";
    int length=alphabet.length();
    StringBuilder build=new StringBuilder();
        //loop within to create the actual string we will add to rand
        for(int i=0; i<12;i++){
            double ch=(length-1)*Math.random();//We will multiply our length by Math.random since it returns a number between 0 and 1
            int chI=(int)Math.round(ch);//round the value to a whole number for index
            build.append(alphabet.charAt(chI));//add that char to our stringbuilder
        }
        return build.toString();

    }
}
