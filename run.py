from portfolio import app
import os

if __name__ == '__main__':
    app.run(debug=True,host=os.getenv('IP', '0.0.0.0'), 
            port=int(os.getenv('PORT', 4444)))

# changes